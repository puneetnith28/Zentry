import ipaddress
import socket
from urllib.parse import urlparse

from app.core.outbound import is_prohibited_ip


class TargetValidationError(ValueError):
    pass


def validate_scan_target(target: str, *, block_private: bool = True) -> str:
    """
    Validate and normalize a scan target URL.

    Enforces:
    - Rejection of embedded credentials (e.g. user:pass@host).
    - Lowercase hostname canonicalization.
    - Valid port range (1..65535).
    - http/https scheme enforcement.
    - SSRF destination checks when block_private is True.

    Returns the normalized URL string. Raises TargetValidationError on invalid
    or blocked targets.
    """
    stripped = target.strip()
    if not stripped:
        raise TargetValidationError("Target URL is required")

    parsed = urlparse(stripped if "://" in stripped else f"https://{stripped}")
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise TargetValidationError("Target must use http or https scheme")

    # Reject embedded credentials in authority or URL string
    if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
        raise TargetValidationError("Embedded credentials in target URL are prohibited")

    raw_host = parsed.hostname
    if not raw_host:
        raise TargetValidationError("Target must include a valid hostname")

    host = raw_host.lower()
    if any(c.isspace() for c in host) or host.startswith(".") or host.endswith("."):
        raise TargetValidationError("Target must include a valid hostname")

    # Validate port bounds if port is explicitly provided
    try:
        port = parsed.port
    except ValueError as exc:
        raise TargetValidationError(f"Invalid port number: {exc}") from exc

    if port is not None and not (1 <= port <= 65535):
        raise TargetValidationError(f"Invalid port number: {port}")

    if block_private:
        is_ip = False
        addr = None
        try:
            addr = ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            pass

        if is_ip and addr is not None:
            if is_prohibited_ip(addr):
                raise TargetValidationError(
                    "Scanning private or loopback addresses is not allowed"
                )

        try:
            for info in socket.getaddrinfo(host, None):
                sockaddr = info[4]
                ip_str = sockaddr[0]
                addr = ipaddress.ip_address(ip_str)
                if is_prohibited_ip(addr):
                    raise TargetValidationError(
                        f"Target hostname resolves to private address: {ip_str}"
                    )
        except socket.gaierror as exc:
            raise TargetValidationError(
                f"Unable to resolve hostname: {host}"
            ) from exc

    normalized = f"{scheme}://{host}"
    if parsed.port:
        normalized += f":{parsed.port}"
    if parsed.path and parsed.path != "/":
        normalized += parsed.path

    return normalized
