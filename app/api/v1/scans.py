from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, get_db
from app.core.config import get_settings
from app.core.rate_limit import rate_limit_scans
from app.core.target_validation import TargetValidationError, validate_scan_target
from app.db.models import ScanJob, ScanStatusEnum, User
from app.schemas.scan import (
    FindingSummary,
    ScanCreateRequest,
    ScanCreateResponse,
    ScanDetailResponse,
    ScanResultPayload,
)
from app.worker.tasks import scan_task

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post(
    "/",
    response_model=ScanCreateResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(rate_limit_scans)],
)
def create_scan(
    body: ScanCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ScanCreateResponse:
    settings = get_settings()
    target_str = str(body.target)
    try:
        normalized = validate_scan_target(
            target_str, block_private=settings.block_private_targets
        )
    except TargetValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    # Enforce concurrent active scan quota per user
    if not current_user.is_superuser:
        active_count = (
            db.query(ScanJob)
            .filter(
                ScanJob.user_id == current_user.id,
                ScanJob.status.in_([ScanStatusEnum.PENDING, ScanStatusEnum.RUNNING]),
            )
            .count()
        )
        if active_count >= settings.max_active_scans_per_user:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Active scan quota exceeded. Maximum {settings.max_active_scans_per_user} concurrent scans allowed.",
            )

    job = ScanJob(
        user_id=current_user.id,
        target_url=normalized,
        status=ScanStatusEnum.PENDING,
        options=body.options.model_dump(),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    scan_task.delay(str(job.id))

    return ScanCreateResponse(scan_id=job.id, status=job.status)


@router.get(
    "/{scan_id}",
    response_model=ScanDetailResponse,
)
def get_scan(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ScanDetailResponse:
    job = db.get(ScanJob, scan_id)
    if job is None or (job.user_id != current_user.id and not current_user.is_superuser):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    result: ScanResultPayload | None = None
    if job.result_payload:
        summary_data = job.result_payload.get("summary", {})
        result = ScanResultPayload(
            target=job.result_payload.get("target", job.target_url),
            scanned_at=job.result_payload.get("scanned_at", ""),
            modules=job.result_payload.get("modules", {}),
            summary=FindingSummary(**summary_data),
        )

    return ScanDetailResponse(
        scan_id=job.id,
        target_url=job.target_url,
        status=job.status,
        created_at=job.created_at,
        updated_at=job.updated_at,
        result=result,
        error_message=job.error_message,
    )
