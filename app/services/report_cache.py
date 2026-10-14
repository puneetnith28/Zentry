"""Private, secure filesystem cache for compiled PDF reports to avoid redundant compilation."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from uuid import UUID

from app.core.config import get_settings

logger = logging.getLogger(__name__)


def _get_cache_dir() -> Path:
    settings = get_settings()
    cache_path = Path(settings.report_cache_dir).resolve()
    if not cache_path.exists():
        cache_path.mkdir(parents=True, exist_ok=True, mode=0o700)
    else:
        try:
            cache_path.chmod(0o700)
        except OSError:
            pass
    return cache_path


def _get_report_path(scan_id: str | UUID) -> Path:
    clean_id = str(scan_id).strip()
    clean_id = os.path.basename(clean_id)
    return _get_cache_dir() / f"{clean_id}.pdf"


def get_cached_report(scan_id: str | UUID) -> bytes | None:
    """Retrieve cached PDF bytes for a scan if present, or None on cache miss."""
    try:
        report_file = _get_report_path(scan_id)
        if report_file.is_file():
            logger.debug("Serving cached PDF report for scan %s", scan_id)
            return report_file.read_bytes()
    except Exception as exc:
        logger.warning("Failed reading cached report for scan %s: %s", scan_id, exc)
    return None


def set_cached_report(scan_id: str | UUID, pdf_bytes: bytes) -> None:
    """Atomically store compiled PDF bytes in private cache with 0o600 permissions."""
    try:
        target_path = _get_report_path(scan_id)
        cache_dir = target_path.parent
        with NamedTemporaryFile(dir=str(cache_dir), delete=False, mode="wb") as tmp:
            tmp.write(pdf_bytes)
            tmp_path = Path(tmp.name)
        try:
            tmp_path.chmod(0o600)
        except OSError:
            pass
        tmp_path.replace(target_path)
        logger.debug("Cached PDF report for scan %s (%d bytes)", scan_id, len(pdf_bytes))
    except Exception as exc:
        logger.warning("Failed writing cached report for scan %s: %s", scan_id, exc)


def invalidate_cached_report(scan_id: str | UUID) -> bool:
    """Invalidate and delete cached report for a scan. Returns True if file was deleted."""
    try:
        report_file = _get_report_path(scan_id)
        if report_file.exists():
            report_file.unlink()
            logger.debug("Invalidated cached report for scan %s", scan_id)
            return True
    except Exception as exc:
        logger.warning("Failed invalidating cached report for scan %s: %s", scan_id, exc)
    return False


def clear_report_cache() -> int:
    """Clear all cached reports. Useful for tests and cache maintenance."""
    count = 0
    try:
        cache_dir = _get_cache_dir()
        for f in cache_dir.glob("*.pdf"):
            try:
                f.unlink()
                count += 1
            except OSError:
                pass
    except Exception as exc:
        logger.warning("Failed clearing report cache: %s", exc)
    return count
