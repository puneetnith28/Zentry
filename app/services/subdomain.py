"""
Passive subdomain discovery service.

Uses certificate transparency logs via crt.sh for fast, robust, and safe
passive discovery without active DNS probing or brute-forcing.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Final
import ipaddress
from urllib.parse import urlparse

import httpx

from app.core.outbound import (
    DNSResolutionError,
    ProhibitedDestinationError,
    ResponseBodyTooLargeError,
    create_safe_async_client,
    is_prohibited_ip,
    parse_bounded_json,
)

from app.services.common import (
    Finding,
    FindingSeverity,
    ModuleScanError,
    ModuleScanStatus,
    serialize,
)

logger = logging.getLogger(__name__)

CRTSH_URL: Final[str] = "https://crt.sh/"
DEFAULT_TIMEOUT: Final[float] = 60.0
MAX_RESULTS: Final[int] = 200
MAX_CRTSH_RESPONSE_BYTES: Final[int] = 2 * 1024 * 1024  # 2 MB payload cap


_SUBDOMAIN_RE: Final[re.Pattern[str]] = re.compile(
    r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$", re.IGNORECASE
)
"""Strict RFC 1035/1123 hostname label validation regex."""


@dataclass(frozen=True, slots=True)
class SubdomainEntry:
    """A single discovered subdomain."""

    hostname: str
    source: str
    status: str


@dataclass(frozen=True, slots=True)
class SubdomainScanResult:
    """Complete result for the subdomain discovery module."""

    status: ModuleScanStatus
    target: str
    subdomains: list[SubdomainEntry] = field(default_factory=list)
    total_discovered: int = 0
    findings: list[Finding] = field(default_factory=list)
    error: ModuleScanError | None = None

    def to_dict(self) -> dict[str, Any]:
        return serialize(self)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_domain(target: str) -> str:
    """Extract a clean, lower-case domain name from *target*.

    Accepts a URL (``https://www.example.com/path``), a host+port
    (``example.com:443``) or a bare hostname (``example.com``).
    """
    stripped = target.strip()
    if "://" in stripped:
        parsed = urlparse(stripped)
        host = parsed.hostname
    else:
        host = stripped.split("/")[0].split(":")[0]

    if not host:
        raise ValueError(f"Invalid target: {target!r}")

    return host.rstrip(".").lower()


def _is_valid_subdomain(candidate: str, domain: str) -> bool:
    """Return True when *candidate* is a valid DNS subdomain of *domain* per RFC 1035/1123."""
    if not candidate or not domain:
        return False

    cd = candidate.strip().lower().rstrip(".")
    dm = domain.strip().lower().rstrip(".")

    if not cd or not dm:
        return False

    if len(cd) > 253:
        return False

    if cd == dm:
        return False

    if any(char in cd for char in ("*", "@", "/", "\\", ":", " ", "\t", "\n", "\r")):
        return False

    if not cd.endswith(f".{dm}"):
        return False

    subdomain_part = cd[: -(len(dm) + 1)]
    if not subdomain_part:
        return False

    labels = cd.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not _SUBDOMAIN_RE.match(label):
            return False

    return True


async def _fetch_crtsh(
    domain: str,
    timeout: float = DEFAULT_TIMEOUT,
    client: httpx.AsyncClient | None = None,
) -> tuple[list[str], ModuleScanError | None]:
    """Query crt.sh certificate transparency logs for subdomains of *domain*."""
    params = {"q": f"%.{domain}", "output": "json"}
    headers = {"User-Agent": "Zentry-Security-Scanner/1.0"}
    try:
        if client is not None:
            response = await client.get(CRTSH_URL, params=params, headers=headers)
            response.raise_for_status()
            data = parse_bounded_json(response, max_bytes=MAX_CRTSH_RESPONSE_BYTES)
        else:
            async with create_safe_async_client(timeout=timeout) as safe_client:
                response = await safe_client.get(CRTSH_URL, params=params, headers=headers)
                response.raise_for_status()
                data = parse_bounded_json(response, max_bytes=MAX_CRTSH_RESPONSE_BYTES)
    except httpx.TimeoutException as exc:
        logger.warning("crt.sh query timed out for %s: %s", domain, exc)
        return [], ModuleScanError(code="PROVIDER_TIMEOUT", message=f"crt.sh query timed out: {exc}")
    except ResponseBodyTooLargeError as exc:
        logger.warning("crt.sh response payload exceeded maximum size for %s: %s", domain, exc)
        return [], ModuleScanError(
            code="PROVIDER_PAYLOAD_TOO_LARGE",
            message=f"crt.sh response payload exceeded maximum size: {exc}",
        )
    except httpx.HTTPStatusError as exc:

        logger.warning("crt.sh returned HTTP error for %s: %s", domain, exc)
        return [], ModuleScanError(
            code="PROVIDER_ERROR",
            message=f"crt.sh returned HTTP {exc.response.status_code}: {exc}",
        )
    except (ProhibitedDestinationError, DNSResolutionError) as exc:
        logger.warning("crt.sh destination error for %s: %s", domain, exc)
        return [], ModuleScanError(code="PROHIBITED_DESTINATION", message=str(exc))
    except httpx.RequestError as exc:
        logger.warning("crt.sh connection failed for %s: %s", domain, exc)
        return [], ModuleScanError(code="PROVIDER_UNAVAILABLE", message=f"crt.sh connection failed: {exc}")
    except (ValueError, TypeError) as exc:
        logger.warning("crt.sh returned invalid JSON for %s: %s", domain, exc)
        return [], ModuleScanError(code="PROVIDER_MALFORMED_RESPONSE", message=f"crt.sh invalid JSON: {exc}")
    except Exception as exc:
        logger.warning("crt.sh unexpected failure for %s: %s", domain, exc)
        return [], ModuleScanError(code="SCAN_FAILED", message=str(exc))

    if not isinstance(data, list):
        logger.warning("crt.sh returned unexpected payload for %s: %r", domain, type(data))
        return [], ModuleScanError(
            code="PROVIDER_MALFORMED_RESPONSE",
            message=f"crt.sh returned non-list JSON payload ({type(data).__name__})",
        )

    names: list[str] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        name_val = entry.get("name_value")
        if isinstance(name_val, str):
            for line in name_val.splitlines():
                clean = line.strip().lower()
                if clean:
                    names.append(clean)
    return names, None


def _deduplicate(entries: list[str]) -> list[str]:
    """Stable deduplication preserving first-occurrence order."""
    seen: set[str] = set()
    out: list[str] = []
    for e in entries:
        if e not in seen:
            seen.add(e)
            out.append(e)
    return out


def _derive_findings(discovered_count: int) -> list[Finding]:
    """Build informational findings based on how many subdomains were found."""
    if discovered_count == 0:
        return [
            Finding(
                code="NO_SUBDOMAINS_DISCOVERED",
                severity=FindingSeverity.INFO,
                message="No subdomains discovered via passive enumeration",
            )
        ]

    findings: list[Finding] = [
        Finding(
            code="SUBDOMAINS_DISCOVERED",
            severity=FindingSeverity.INFO,
            message=f"{discovered_count} subdomain(s) discovered via passive enumeration",
        )
    ]

    if discovered_count > 20:
        findings.append(
            Finding(
                code="LARGE_ATTACK_SURFACE",
                severity=FindingSeverity.MEDIUM,
                message=(
                    f"{discovered_count} subdomains found — "
                    f"large enumeration increases potential attack surface"
                ),
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def discover_subdomains_async(
    target: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Passively enumerate subdomains for *target*.

    Uses certificate transparency logs via crt.sh.
    No brute-force, DNS query flooding, or aggressive probing is performed.

    Returns a JSON-serializable dict consistent with the project's module
    result format.
    """
    try:
        domain = _extract_domain(target)
    except ValueError as exc:
        return SubdomainScanResult(
            status=ModuleScanStatus.ERROR,
            target=target,
            error=ModuleScanError(code="INVALID_TARGET", message=str(exc)),
        ).to_dict()

    try:
        ip_obj = ipaddress.ip_address(domain)
        if is_prohibited_ip(ip_obj):
            return SubdomainScanResult(
                status=ModuleScanStatus.ERROR,
                target=target,
                error=ModuleScanError(
                    code="PROHIBITED_DESTINATION",
                    message=f"Subdomain scanning cannot target prohibited IP destination: {domain}",
                ),
            ).to_dict()
        return SubdomainScanResult(
            status=ModuleScanStatus.ERROR,
            target=target,
            error=ModuleScanError(
                code="INVALID_TARGET",
                message=f"Subdomain scanning requires a domain name, not an IP address: {domain}",
            ),
        ).to_dict()
    except ValueError:
        pass

    logger.info("Subdomain discovery starting for %s", domain)

    raw_names, error = await _fetch_crtsh(domain, timeout=timeout, client=client)
    if error is not None:
        logger.warning("Subdomain discovery failed for %s: %s", domain, error.message)
        return SubdomainScanResult(
            status=ModuleScanStatus.ERROR,
            target=domain,
            subdomains=[],
            total_discovered=0,
            findings=[],
            error=error,
        ).to_dict()

    validated: list[str] = [
        name for name in raw_names if _is_valid_subdomain(name, domain)
    ]

    unique = _deduplicate(validated)
    unique.sort()

    if len(unique) > MAX_RESULTS:
        unique = unique[:MAX_RESULTS]

    entries = [
        SubdomainEntry(hostname=sd, source="crt.sh", status="discovered")
        for sd in unique
    ]

    findings = _derive_findings(len(entries))

    logger.info(
        "Subdomain discovery complete for %s: %d subdomain(s)",
        domain,
        len(entries),
    )

    return SubdomainScanResult(
        status=ModuleScanStatus.SUCCESS,
        target=domain,
        subdomains=entries,
        total_discovered=len(entries),
        findings=findings,
    ).to_dict()


def discover_subdomains(
    target: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Synchronous wrapper around :func:`discover_subdomains_async`."""
    return asyncio.run(
        discover_subdomains_async(target, timeout=timeout, client=client)
    )
