import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

from app.api.dependencies import get_current_user, get_db
from app.core.celery_app import get_queue_depth
from app.core.config import get_settings
from app.core.rate_limit import rate_limit_scans
from app.core.target_validation import TargetValidationError, validate_scan_target
from app.db.models import ScanJob, ScanStatusEnum, User
from app.schemas.scan import (
    FindingSummary,
    PaginatedScanHistoryResponse,
    ScanCreateRequest,
    ScanCreateResponse,
    ScanDetailResponse,
    ScanResultPayload,
    ScanSummaryItem,
)
from app.worker.tasks import scan_task

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get(
    "/",
    response_model=PaginatedScanHistoryResponse,
)
def list_scans(
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
    status_filter: ScanStatusEnum | None = Query(
        default=None, alias="status", description="Filter scans by status"
    ),
    target_search: str | None = Query(
        default=None,
        alias="target",
        max_length=255,
        description="Search by target URL substring",
    ),
    sort_order: str = Query(
        default="desc",
        pattern="^(asc|desc)$",
        description="Sort order by creation time",
    ),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PaginatedScanHistoryResponse:
    query = db.query(ScanJob)
    if not current_user.is_superuser:
        query = query.filter(ScanJob.user_id == current_user.id)

    if status_filter is not None:
        query = query.filter(ScanJob.status == status_filter)

    if target_search:
        clean_target = target_search.strip()
        if clean_target:
            query = query.filter(
                ScanJob.target_url.contains(clean_target, autoescape=True)
            )

    total = query.count()
    offset = (page - 1) * page_size

    if sort_order == "asc":
        query = query.order_by(ScanJob.created_at.asc())
    else:
        query = query.order_by(ScanJob.created_at.desc())

    jobs = query.offset(offset).limit(page_size).all()

    items: list[ScanSummaryItem] = []
    for job in jobs:
        summary: FindingSummary | None = None
        if job.result_payload and "summary" in job.result_payload:
            summary = FindingSummary(**job.result_payload["summary"])

        items.append(
            ScanSummaryItem(
                scan_id=job.id,
                target_url=job.target_url,
                status=job.status,
                created_at=job.created_at,
                updated_at=job.updated_at,
                started_at=job.started_at,
                finished_at=job.finished_at,
                duration_seconds=job.duration_seconds,
                user_id=job.user_id,
                summary=summary,
                error_message=job.error_message,
            )
        )

    total_pages = (total + page_size - 1) // page_size if total > 0 else 0

    return PaginatedScanHistoryResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


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

    # Check broker queue depth for backpressure protection
    current_depth = get_queue_depth()
    if current_depth >= settings.max_queue_depth:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="System is currently experiencing high load. Please try again shortly.",
            headers={"Retry-After": "30"},
        )
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
                ScanJob.status.in_(ScanStatusEnum.active_statuses()),
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

    try:
        scan_task.delay(str(job.id))
    except Exception as exc:
        logger.error("Failed to enqueue scan task for job %s: %s", job.id, exc)
        job.transition_to(ScanStatusEnum.FAILED)
        job.error_message = "Failed to dispatch scan to background worker queue"
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to enqueue scan task. Broker is temporarily unavailable.",
            headers={"Retry-After": "30"},
        )

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
        started_at=job.started_at,
        finished_at=job.finished_at,
        duration_seconds=job.duration_seconds,
        user_id=job.user_id,
        result=result,
        error_message=job.error_message,
    )


@router.post(
    "/{scan_id}/cancel",
    response_model=ScanDetailResponse,
)
def cancel_scan(
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

    # Check if scan is already in a terminal state
    if job.status in ScanStatusEnum.terminal_statuses():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel scan in terminal status '{job.status.value}'",
        )

    # Transition to CANCELLED atomically
    job.transition_to(ScanStatusEnum.CANCELLED)
    job.error_message = "Scan was cancelled by user request"
    db.commit()
    db.refresh(job)

    # Attempt to revoke Celery background task if queued or running
    try:
        from app.core.celery_app import celery_app
        celery_app.control.revoke(str(job.id), terminate=True)
    except Exception as exc:
        logger.warning("Failed to revoke Celery task for scan %s: %s", job.id, exc)

    return get_scan(scan_id=scan_id, current_user=current_user, db=db)

