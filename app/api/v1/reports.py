from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, get_db
from app.db.models import ScanJob, ScanStatusEnum, User
from app.services.pdf_generator import generate_pdf

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get(
    "/{scan_id}/pdf",
    response_class=Response,
)
def get_scan_pdf(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    job = db.get(ScanJob, scan_id)
    if job is None or (job.user_id != current_user.id and not current_user.is_superuser):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    if (job.status in (ScanStatusEnum.PENDING, ScanStatusEnum.RUNNING)) or (
        job.status == ScanStatusEnum.COMPLETED and not job.result_payload
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Scan is not completed or has no results",
        )

    try:
        payload = job.result_payload or {}
        pdf_bytes = generate_pdf(
            payload,
            scan_id=str(job.id),
            target_url=job.target_url,
            scan_status=job.status.value,
            error_message=job.error_message,
        )
    except Exception as e:
        import logging
        logging.getLogger(__name__).exception("Failed to generate PDF report for scan %s: %s", scan_id, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate PDF report.",
        )
    filename = f"zentry-report-{scan_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
