"""Generate PDF security reports from scan payloads using WeasyPrint with strict resource bounds."""

from __future__ import annotations

import concurrent.futures
import json
import logging
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
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


def _severity_badge_class(severity: str) -> str:
    return {
        "critical": "badge-critical",
        "high": "badge-high",
        "medium": "badge-medium",
        "low": "badge-low",
        "info": "badge-info",
    }.get(severity, "badge-info")


def render_report_html(
    payload: dict[str, Any],
    *,
    scan_id: str,
    target_url: str,
    max_findings: int = DEFAULT_MAX_FINDINGS,
    max_json_chars: int = DEFAULT_MAX_JSON_CHARS,
) -> str:
    template = _env.get_template("report.html")
    modules = payload.get("modules", {})
    all_findings: list[dict[str, Any]] = []

    sanitized_modules: dict[str, Any] = {}
    for module_name, module_data in modules.items():
        if not isinstance(module_data, dict):
            sanitized_modules[module_name] = module_data
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

    return template.render(
        scan_id=scan_id,
        target_url=target_url,
        scanned_at=payload.get("scanned_at", ""),
        summary=payload.get("summary", {}),
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
