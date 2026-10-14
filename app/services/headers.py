"""
HTTP security header analysis service.

Uses httpx for async HTTP requests. No subprocess or shell execution.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Final
from urllib.parse import urlparse

import httpx

from app.core.outbound import (
    DEFAULT_HEADERS_MAX_RESPONSE_BYTES,
    DNSResolutionError,
    MaxRedirectsExceededError,
    ProhibitedDestinationError,
    ResponseBodyTooLargeError,
    safe_stream_request,
)
from app.services.common import (
    Finding,
    FindingSeverity,
    ModuleScanError,
    ModuleScanStatus,
    serialize,
)

DEFAULT_TIMEOUT: Final[float] = 10.0
SECURITY_HEADERS: Final[dict[str, tuple[str, FindingSeverity]]] = {
    "strict-transport-security": (
        "MISSING_HSTS",
        FindingSeverity.HIGH,
    ),
    "content-security-policy": (
        "MISSING_CSP",
        FindingSeverity.MEDIUM,
    ),
    "x-frame-options": (
        "MISSING_X_FRAME_OPTIONS",
        FindingSeverity.MEDIUM,
    ),
    "x-content-type-options": (
        "MISSING_X_CONTENT_TYPE_OPTIONS",
        FindingSeverity.LOW,
    ),
    "referrer-policy": (
        "MISSING_REFERRER_POLICY",
        FindingSeverity.LOW,
    ),
    "permissions-policy": (
        "MISSING_PERMISSIONS_POLICY",
        FindingSeverity.INFO,
    ),
}


@dataclass(frozen=True, slots=True)
class CookieInfo:
    name: str
    secure: bool
    httponly: bool
    samesite: str | None
    domain: str | None = None
    path: str | None = None


@dataclass(frozen=True, slots=True)
class HeadersScanResult:
    status: ModuleScanStatus
    target: str
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[CookieInfo] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    error: ModuleScanError | None = None

    def to_dict(self) -> dict[str, Any]:
        return serialize(self)


def _normalize_url(target: str) -> str:
    stripped = target.strip()
    if "://" not in stripped:
        return f"https://{stripped}"
    return stripped


def _parse_cookies(response: httpx.Response) -> list[CookieInfo]:
    cookies: list[CookieInfo] = []
    for header_value in response.headers.get_list("set-cookie"):
        parts = [p.strip() for p in header_value.split(";")]
        if not parts:
            continue
        name_value = parts[0]
        if "=" not in name_value:
            continue
        name, _ = name_value.split("=", 1)
        attrs = {p.split("=")[0].lower(): True for p in parts[1:] if p}
        samesite = None
        domain = None
        path = None
        for part in parts[1:]:
            lower_part = part.lower().strip()
            if lower_part.startswith("samesite="):
                samesite = part.split("=", 1)[1].strip()
            elif lower_part.startswith("domain="):
                domain = part.split("=", 1)[1].strip()
            elif lower_part.startswith("path="):
                path = part.split("=", 1)[1].strip()
        cookies.append(
            CookieInfo(
                name=name.strip(),
                secure="secure" in attrs,
                httponly="httponly" in attrs,
                samesite=samesite,
                domain=domain,
                path=path,
            )
        )
    return cookies


def _analyze_headers(
    response_headers: dict[str, str],
    cookies: list[CookieInfo],
    *,
    is_https: bool,
) -> list[Finding]:
    """Inspects the HTTP response headers for missing or misconfigured security protections."""
    findings: list[Finding] = []
    lower_headers = {k.lower(): v for k, v in response_headers.items()}

    # 1. Baseline required security headers presence
    for header_name, (code, severity) in SECURITY_HEADERS.items():
        if header_name not in lower_headers:
            # HSTS is only applicable over HTTPS, ignore if it's plain HTTP
            if header_name == "strict-transport-security" and not is_https:
                continue
            findings.append(
                Finding(
                    code=code,
                    severity=severity,
                    message=f"Missing security header: {header_name}",
                )
            )

    # 2. Strict-Transport-Security (HSTS) detailed checks
    hsts = lower_headers.get("strict-transport-security", "")
    if hsts and is_https:
        clean_hsts = hsts.lower().replace(" ", "")
        if "max-age=0" in clean_hsts:
            findings.append(
                Finding(
                    code="HSTS_DISABLED",
                    severity=FindingSeverity.HIGH,
                    message="HSTS max-age is set to 0 (disabled)",
                )
            )
        else:
            # Check max-age duration
            max_age_val = None
            for directive in hsts.split(";"):
                directive = directive.strip().lower()
                if directive.startswith("max-age="):
                    val_str = directive.split("=", 1)[1].strip()
                    if val_str.isdigit():
                        max_age_val = int(val_str)
                    break
            if max_age_val is not None and max_age_val < 15552000:
                findings.append(
                    Finding(
                        code="HSTS_SHORT_MAX_AGE",
                        severity=FindingSeverity.LOW,
                        message=f"HSTS max-age ({max_age_val}s) is less than recommended 6 months (15552000s)",
                    )
                )
            if "includesubdomains" not in clean_hsts:
                findings.append(
                    Finding(
                        code="HSTS_NO_SUBDOMAINS",
                        severity=FindingSeverity.LOW,
                        message="HSTS header does not include 'includeSubDomains' directive",
                    )
                )

    # 3. Content-Security-Policy detailed checks
    csp = lower_headers.get("content-security-policy", "")
    if csp:
        lower_csp = csp.lower()
        if "'unsafe-inline'" in lower_csp or "'unsafe-eval'" in lower_csp:
            findings.append(
                Finding(
                    code="CSP_UNSAFE_DIRECTIVES",
                    severity=FindingSeverity.MEDIUM,
                    message="Content-Security-Policy contains 'unsafe-inline' or 'unsafe-eval'",
                )
            )
        if "default-src *" in lower_csp or "script-src *" in lower_csp:
            findings.append(
                Finding(
                    code="CSP_WILDCARD_SOURCE",
                    severity=FindingSeverity.MEDIUM,
                    message="Content-Security-Policy permits wildcard '*' source in script or default rules",
                )
            )

    # 4. X-Frame-Options detailed checks
    raw_xfo = lower_headers.get("x-frame-options", "").strip()
    if raw_xfo:
        upper_xfo = raw_xfo.upper()
        if upper_xfo in ("ALLOWALL", "ALLOW"):
            findings.append(
                Finding(
                    code="WEAK_X_FRAME_OPTIONS",
                    severity=FindingSeverity.MEDIUM,
                    message="X-Frame-Options allows framing",
                )
            )
        elif upper_xfo not in ("DENY", "SAMEORIGIN") and not upper_xfo.startswith("ALLOW-FROM"):
            findings.append(
                Finding(
                    code="MISCONFIGURED_X_FRAME_OPTIONS",
                    severity=FindingSeverity.LOW,
                    message=f"X-Frame-Options value '{raw_xfo}' is deprecated or non-standard",
                )
            )

    # 5. X-Content-Type-Options detailed checks
    raw_xcto = lower_headers.get("x-content-type-options", "").strip()
    if raw_xcto and raw_xcto.lower() != "nosniff":
        findings.append(
            Finding(
                code="MISCONFIGURED_X_CONTENT_TYPE_OPTIONS",
                severity=FindingSeverity.LOW,
                message=f"X-Content-Type-Options value '{raw_xcto}' is invalid, expected 'nosniff'",
            )
        )

    # 6. Server software version disclosure
    server = lower_headers.get("server", "")
    if server:
        findings.append(
            Finding(
                code="SERVER_HEADER_DISCLOSURE",
                severity=FindingSeverity.INFO,
                message=f"Server header discloses: {server[:120]}",
            )
        )

    # 7. Scrutinize every cookie for secure transmission flags
    for cookie in cookies:
        issues: list[str] = []
        if not cookie.secure and is_https:
            issues.append("missing Secure")
        if not cookie.httponly:
            issues.append("missing HttpOnly")
        if cookie.samesite is None:
            issues.append("missing SameSite")
        else:
            s_val = cookie.samesite.strip().lower()
            if s_val not in ("strict", "lax", "none"):
                issues.append(f"invalid SameSite value '{cookie.samesite}'")
            elif s_val == "none" and not cookie.secure:
                issues.append("SameSite=None requires Secure")

        if cookie.name.startswith("__Host-"):
            if not cookie.secure:
                issues.append("__Host- requires Secure")
            if cookie.domain:
                issues.append("__Host- must not set Domain")
        elif cookie.name.startswith("__Secure-"):
            if not cookie.secure:
                issues.append("__Secure- requires Secure")

        if issues:
            findings.append(
                Finding(
                    code="INSECURE_COOKIE",
                    severity=FindingSeverity.MEDIUM,
                    message=f"Cookie '{cookie.name}': {', '.join(issues)}",
                )
            )

    return findings


async def inspect_headers_async(
    target: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Fetch and analyze HTTP security headers for *target* safely through outbound gateway."""
    url = _normalize_url(target)
    parsed = urlparse(url)
    is_https = parsed.scheme == "https"

    try:
        # We don't follow redirects here because we want to analyze the exact endpoint requested.
        # Often, a redirect itself is missing security headers before sending you to the secure site.
        # We stream the request so only HTTP headers are inspected without buffering response body.
        async with safe_stream_request(
            method="GET",
            url=url,
            client=client,
            follow_redirects=False,
            timeout=timeout,
            max_response_bytes=DEFAULT_HEADERS_MAX_RESPONSE_BYTES,
        ) as response:
            status_code = response.status_code
            headers = dict(response.headers)
            cookies = _parse_cookies(response)
    except (ProhibitedDestinationError, DNSResolutionError) as exc:
        return HeadersScanResult(
            status=ModuleScanStatus.ERROR,
            target=url,
            error=ModuleScanError(code="PROHIBITED_DESTINATION", message=str(exc)),
        ).to_dict()
    except ResponseBodyTooLargeError as exc:
        return HeadersScanResult(
            status=ModuleScanStatus.ERROR,
            target=url,
            error=ModuleScanError(code="RESPONSE_TOO_LARGE", message=str(exc)),
        ).to_dict()
    except (httpx.RequestError, MaxRedirectsExceededError) as exc:
        return HeadersScanResult(
            status=ModuleScanStatus.ERROR,
            target=url,
            error=ModuleScanError(code="REQUEST_FAILED", message=str(exc)),
        ).to_dict()

    findings = _analyze_headers(headers, cookies, is_https=is_https)

    return HeadersScanResult(
        status=ModuleScanStatus.SUCCESS,
        target=url,
        status_code=status_code,
        headers={k: v for k, v in headers.items()},
        cookies=cookies,
        findings=findings,
    ).to_dict()


def inspect_headers(
    target: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    return asyncio.run(inspect_headers_async(target, timeout=timeout, client=client))
