"""Generate PDF security reports from scan payloads using WeasyPrint with strict resource bounds."""

from __future__ import annotations

import concurrent.futures
import json
import logging
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from jinja2 import Environment, FileSystemLoader

from app.services.common import calculate_risk_score

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=True,
)

DEFAULT_MAX_FINDINGS: int = 100
DEFAULT_PDF_TIMEOUT_SECONDS: float = 30.0
DEFAULT_MAX_JSON_CHARS: int = 20000
MAX_EVIDENCE_RENDER_CHARS: int = 1000

SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


class PDFGenerationTimeoutError(Exception):
    """Raised when PDF compilation exceeds allowed wall-clock duration."""


def sanitize_target_url_for_report(target_url: str) -> str:
    """
    Sanitize target URL for report presentation.
    1. Redacts embedded credentials (user:pass).
    2. Neutralizes non-http/https execution schemes (e.g. javascript:, data:, vbscript:).
    """
    if not target_url:
        return ""
    stripped = target_url.strip()
    try:
        lower = stripped.lower()
        for dangerous in ("javascript:", "data:", "vbscript:", "file:", "blob:", "about:"):
            if lower.startswith(dangerous):
                return f"[blocked-scheme:{dangerous[:-1]}]"

        if "://" in stripped:
            parsed = urlsplit(stripped)
            scheme = parsed.scheme.lower()
            if scheme not in ("http", "https"):
                return f"[blocked-scheme:{scheme}]"
            netloc = parsed.hostname or ""
            if parsed.port:
                netloc = f"{netloc}:{parsed.port}"
            return urlunsplit((scheme, netloc, parsed.path, parsed.query, parsed.fragment))
        else:
            if "@" in stripped:
                stripped = stripped.split("@", 1)[-1]
            return stripped
    except Exception:
        if "@" in stripped:
            return stripped.split("@", 1)[-1]
        return stripped


def _severity_badge_class(severity: str) -> str:
    return {
        "critical": "badge-critical",
        "high": "badge-high",
        "medium": "badge-medium",
        "low": "badge-low",
        "info": "badge-info",
    }.get(str(severity).lower(), "badge-info")


def render_report_html(
    payload: dict[str, Any],
    *,
    scan_id: str,
    target_url: str,
    scan_status: str | None = None,
    error_message: str | None = None,
    max_findings: int = DEFAULT_MAX_FINDINGS,
    max_json_chars: int = DEFAULT_MAX_JSON_CHARS,
) -> str:
    template = _env.get_template("report.html")
    modules = payload.get("modules", {})
    all_findings: list[dict[str, Any]] = []

    safe_target_url = sanitize_target_url_for_report(target_url)

    if scan_status is None:
        scan_status = str(payload.get("status") or "completed")
    if error_message is None:
        error_message = payload.get("error") or payload.get("error_message") or ""

    sanitized_modules: dict[str, Any] = {}
    for module_name, module_data in modules.items():
        if not isinstance(module_data, dict):
            sanitized_modules[module_name] = {"raw": module_data, "status": "unknown"} if module_data is not None else {}
            continue
        mod_copy = dict(module_data)
        if "findings" in mod_copy and isinstance(mod_copy["findings"], list):
            cleaned_findings_list = []
            for f in mod_copy["findings"]:
                if isinstance(f, dict):
                    cf = dict(f)
                    cf["module"] = module_name
                    ev = cf.get("evidence")
                    if ev and isinstance(ev, str) and len(ev) > MAX_EVIDENCE_RENDER_CHARS:
                        cf["evidence"] = ev[:MAX_EVIDENCE_RENDER_CHARS] + "... [truncated]"
                    all_findings.append(cf)
                    cleaned_findings_list.append(cf)
                else:
                    cleaned_findings_list.append(f)
            mod_copy["findings"] = cleaned_findings_list
        sanitized_modules[module_name] = mod_copy

    # Check for partial module failures
    module_status_map = payload.get("summary", {}).get("module_status", {})
    has_partial_module_failures = False
    for m_name, m_data in sanitized_modules.items():
        m_stat = module_status_map.get(m_name)
        if not m_stat and isinstance(m_data, dict):
            m_stat = m_data.get("status")
        if m_stat and str(m_stat).lower() in ("error", "failed", "timeout"):
            has_partial_module_failures = True
            break

    # Sort deterministically by severity priority, then title
    all_findings.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(str(f.get("severity", "")).lower(), 5),
            str(f.get("title", "")),
        )
    )

    total_findings_count = len(all_findings)
    is_truncated = total_findings_count > max_findings
    if is_truncated:
        all_findings = all_findings[:max_findings]

    module_jsons = {}
    for name, data in sanitized_modules.items():
        dumped = json.dumps(data, indent=2, default=str)
        if len(dumped) > max_json_chars:
            dumped = dumped[:max_json_chars] + "\n... [truncated due to size limit]"
        module_jsons[name] = dumped

    summary_dict = payload.get("summary", {})
    risk_score = payload.get("risk_score")
    risk_level = payload.get("risk_level")
    score_version = payload.get("score_version")

    score_obj = payload.get("score")
    if isinstance(score_obj, dict):
        if risk_score is None:
            risk_score = score_obj.get("score")
        if risk_level is None:
            risk_level = score_obj.get("level")
        if score_version is None:
            score_version = score_obj.get("version")
    elif isinstance(score_obj, (int, float)) and risk_score is None:
        risk_score = int(score_obj)

    if risk_score is None and summary_dict:
        calc = calculate_risk_score(summary_dict)
        risk_score = calc.score
        risk_level = calc.level
        score_version = calc.version

    return template.render(
        scan_id=scan_id,
        target_url=safe_target_url,
        scan_status=scan_status,
        error_message=error_message,
        has_partial_module_failures=has_partial_module_failures,
        risk_score=risk_score,
        risk_level=risk_level,
        score_version=score_version,
        scanned_at=payload.get("scanned_at", ""),
        summary=summary_dict,
        modules=sanitized_modules,
        module_jsons=module_jsons,
        all_findings=all_findings,
        total_findings_count=total_findings_count,
        is_truncated=is_truncated,
        max_findings=max_findings,
        severity_badge_class=_severity_badge_class,
    )


def generate_pdf(
    payload: dict[str, Any],
    *,
    scan_id: str,
    target_url: str,
    scan_status: str | None = None,
    error_message: str | None = None,
    timeout: float = DEFAULT_PDF_TIMEOUT_SECONDS,
    max_findings: int = DEFAULT_MAX_FINDINGS,
) -> bytes:
    try:
        from weasyprint import HTML
    except (ImportError, OSError) as e:
        raise RuntimeError(
            "WeasyPrint missing GTK+ libraries (libgobject). "
            "Please start Docker Desktop and run Zentry via Docker, or install GTK+ on Windows."
        ) from e

    html = render_report_html(
        payload,
        scan_id=scan_id,
        target_url=target_url,
        scan_status=scan_status,
        error_message=error_message,
        max_findings=max_findings,
    )

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(lambda: HTML(string=html).write_pdf())
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError as exc:
            logger.error("PDF generation timed out for scan %s after %ss", scan_id, timeout)
            raise PDFGenerationTimeoutError(
                f"PDF compilation exceeded maximum execution budget of {timeout}s"
            ) from exc
