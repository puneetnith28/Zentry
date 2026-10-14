import re
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, get_db
from app.db.models import ScanJob, ScanStatusEnum, User
from app.services.pdf_generator import generate_pdf

router = APIRouter(prefix="/reports", tags=["reports"])


def sanitize_report_filename(target_url: str, scan_id: str) -> str:
    """
    Generate a safe, sanitized filename for PDF report downloads:
    `zentry-report-<sanitized_host>-<scan_id_prefix>.pdf`

    Guarantees:
    - Strips paths, query parameters, fragments, credentials, and ports
    - Neutralizes path traversal sequences (../, ..\\)
    - Removes whitespace, CRLF, and quote characters to prevent header injection
    - Bounds hostname component to at most 40 characters
    - Fallback to 'target' if no valid characters remain
    """
    clean_host = ""
    try:
        raw = str(target_url).strip()
        raw = raw.split("\r")[0].split("\n")[0].strip()
        if "://" in raw:
            parsed = urlsplit(raw)
            host = parsed.hostname or parsed.netloc or ""
        else:
            host = raw.split("/")[0].split(":")[0]
            if "@" in host:
                host = host.split("@")[-1]
        clean_host = re.sub(r"[^a-zA-Z0-9.-]", "_", host)
        clean_host = re.sub(r"_+", "_", clean_host)
        clean_host = clean_host.strip(".-_")
    except Exception:
        clean_host = ""

    if not clean_host:
        clean_host = "target"

    if len(clean_host) > 40:
        clean_host = clean_host[:40].rstrip(".-_")

    scan_id_str = str(scan_id).strip()
    scan_id_prefix = scan_id_str[:8] if len(scan_id_str) >= 8 else scan_id_str
    clean_id = re.sub(r"[^a-zA-Z0-9-]", "", scan_id_prefix)

    return f"zentry-report-{clean_host}-{clean_id}.pdf"


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
    filename = sanitize_report_filename(job.target_url, str(scan_id))
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Type": "application/pdf",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, no-transform, max-age=0, must-revalidate",
        },
    )
