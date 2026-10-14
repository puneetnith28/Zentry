"""Trusted reverse proxy and client IP resolution utilities."""

import ipaddress
import logging
from typing import Sequence
from starlette.requests import Request

from app.core.config import Settings, get_settings

logger = logging.getLogger("zentry.proxy")


def is_ip_in_trusted_list(client_ip: str, trusted_proxies: Sequence[str]) -> bool:
    """
    Check if a given client IP is contained within a list of trusted proxy IPs or CIDR blocks.
    """
    if not client_ip or not trusted_proxies:
        return False

    try:
        parsed_client = ipaddress.ip_address(client_ip.strip())
    except ValueError:
        return False

    for trusted in trusted_proxies:
        trusted_clean = trusted.strip()
        if not trusted_clean:
            continue
        try:
            if "/" in trusted_clean:
                network = ipaddress.ip_network(trusted_clean, strict=False)
                if parsed_client in network:
                    return True
            else:
                target_ip = ipaddress.ip_address(trusted_clean)
                if parsed_client == target_ip:
                    return True
        except ValueError:
            logger.warning("Invalid trusted proxy configuration entry: %s", trusted)
            continue

    return False


def get_client_ip(request: Request, settings: Settings | None = None) -> str:
    """
    Extract the effective client IP address from an incoming HTTP request.

    If the direct connecting peer (request.client.host) is a trusted reverse proxy,
    the client IP is extracted from X-Forwarded-For or X-Real-IP headers.
    If the direct connecting peer is NOT trusted, forwarded headers are ignored
    to prevent client IP spoofing and rate limit bypass.
    """
    if settings is None:
        settings = get_settings()

    direct_ip = request.client.host if request.client else "127.0.0.1"

    if not is_ip_in_trusted_list(direct_ip, settings.trusted_proxies):
        # Peer is not a trusted proxy; do not honor forwarded headers
        return direct_ip

    # Peer is trusted; check X-Forwarded-For first
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        # Format: client, proxy1, proxy2...
        # Take the leftmost valid non-empty IP
        parts = [p.strip() for p in x_forwarded_for.split(",") if p.strip()]
        for part in parts:
            try:
                ipaddress.ip_address(part)
                return part
            except ValueError:
                continue

    # Next check X-Real-IP
    x_real_ip = request.headers.get("x-real-ip")
    if x_real_ip:
        clean_ip = x_real_ip.strip()
        try:
            ipaddress.ip_address(clean_ip)
            return clean_ip
        except ValueError:
            pass

    return direct_ip
