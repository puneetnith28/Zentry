"""
Centralized Outbound Network Policy and Security Controls.

Enforces connection-level destination validation, SSRF defenses,
IP classification, safe DNS resolution, and pinned connections.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Final


class ProhibitedDestinationError(ValueError):
    """Raised when an outbound network destination violates security policy."""
    pass


class DNSResolutionError(ValueError):
    """Raised when DNS resolution for an outbound target fails."""
    pass


# Comprehensive IPv4 prohibited ranges (RFC 1918, 1122, 3927, 5771, 6598, etc.)
PROHIBITED_IPV4_NETWORKS: Final[tuple[ipaddress.IPv4Network, ...]] = (
    ipaddress.ip_network("0.0.0.0/8"),          # Current network / "this host"
    ipaddress.ip_network("10.0.0.0/8"),         # Private RFC 1918
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space / CGNAT RFC 6598
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback RFC 1122
    ipaddress.ip_network("169.254.0.0/16"),     # Link Local RFC 3927 (includes 169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # Private RFC 1918
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments RFC 6890
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1 Documentation RFC 5737
    ipaddress.ip_network("192.88.99.0/24"),     # 6to4 Relay Anycast RFC 7526
    ipaddress.ip_network("192.168.0.0/16"),     # Private RFC 1918
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmark testing RFC 2544
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2 Documentation RFC 5737
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3 Documentation RFC 5737
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast RFC 5771
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved RFC 1112
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast RFC 919
)

# Comprehensive IPv6 prohibited ranges (RFC 4291, 4193, 3849, 6666, etc.)
PROHIBITED_IPV6_NETWORKS: Final[tuple[ipaddress.IPv6Network, ...]] = (
    ipaddress.ip_network("::/128"),             # Unspecified address RFC 4291
    ipaddress.ip_network("::1/128"),            # Loopback RFC 4291
    ipaddress.ip_network("100::/64"),           # Discard-only prefix RFC 6666
    ipaddress.ip_network("2001::/23"),          # IETF protocol assignments
    ipaddress.ip_network("2001:db8::/32"),      # Documentation RFC 3849
    ipaddress.ip_network("2002::/16"),          # 6to4 relay RFC 3056
    ipaddress.ip_network("fc00::/7"),           # Unique Local RFC 4193
    ipaddress.ip_network("fe80::/10"),          # Link-local unicast RFC 4291
    ipaddress.ip_network("ff00::/8"),           # Multicast RFC 4291
)


def parse_ip_address(
    ip_or_str: ipaddress.IPv4Address | ipaddress.IPv6Address | str
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse string or IP object into an IPv4Address or IPv6Address."""
    if isinstance(ip_or_str, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return ip_or_str
    try:
        return ipaddress.ip_address(str(ip_or_str).strip())
    except ValueError as exc:
        raise ProhibitedDestinationError(f"Invalid IP address representation: {ip_or_str}") from exc


def is_prohibited_ip(
    ip_or_str: ipaddress.IPv4Address | ipaddress.IPv6Address | str
) -> bool:
    """
    Deterministically evaluates whether an IP destination is prohibited.
    
    Blocks:
    - Loopback, private, link-local, unspecified, multicast, reserved addresses.
    - Cloud metadata (e.g., 169.254.169.254).
    - IPv4-mapped IPv6 addresses representing prohibited IPv4 destinations.
    """
    try:
        ip = parse_ip_address(ip_or_str)
    except ProhibitedDestinationError:
        return True

    # Check IPv4-mapped IPv6 address (::ffff:w.x.y.z)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return is_prohibited_ip(ip.ipv4_mapped)

    # Standard built-in classification flags
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True

    # Explicit prohibited network range checking
    if isinstance(ip, ipaddress.IPv4Address):
        return any(ip in net for net in PROHIBITED_IPV4_NETWORKS)
    elif isinstance(ip, ipaddress.IPv6Address):
        return any(ip in net for net in PROHIBITED_IPV6_NETWORKS)

    return True


def validate_ip_destination(
    ip_or_str: ipaddress.IPv4Address | ipaddress.IPv6Address | str
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """
    Validate that an IP address is permissible as an outbound scan destination.
    
    Returns the parsed IP address or raises ProhibitedDestinationError.
    """
    ip = parse_ip_address(ip_or_str)
    if is_prohibited_ip(ip):
        raise ProhibitedDestinationError(
            f"Outbound connection to prohibited destination blocked: {ip}"
        )
    return ip


def resolve_public_target(
    hostname: str,
    port: int = 0,
    *,
    family: int = socket.AF_UNSPEC,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    """
    Resolve a hostname and verify that every returned IP address is strictly public.
    
    Enforces safe multi-answer policy: if ANY returned IP address is prohibited,
    the entire target is rejected to protect against DNS rebinding and split-horizon SSRF.
    
    Returns a tuple of validated IP address objects.
    """
    clean_host = hostname.strip().rstrip(".")
    if not clean_host:
        raise DNSResolutionError("Empty hostname provided for DNS resolution")

    # If the target is already an IP address, validate it directly
    try:
        ip = ipaddress.ip_address(clean_host)
        return (validate_ip_destination(ip),)
    except ValueError:
        pass  # Hostname string, proceed with DNS lookup

    try:
        addrinfo = socket.getaddrinfo(
            clean_host,
            port,
            family=family,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise DNSResolutionError(f"Unable to resolve hostname: {clean_host}") from exc

    if not addrinfo:
        raise DNSResolutionError(f"No DNS records returned for hostname: {clean_host}")

    resolved_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    seen: set[str] = set()

    for item in addrinfo:
        sockaddr = item[4]
        ip_str = sockaddr[0]
        if ip_str in seen:
            continue
        seen.add(ip_str)

        try:
            ip = parse_ip_address(ip_str)
        except ProhibitedDestinationError as exc:
            raise ProhibitedDestinationError(
                f"Target {clean_host} resolved to invalid IP address: {ip_str}"
            ) from exc

        if is_prohibited_ip(ip):
            raise ProhibitedDestinationError(
                f"Target {clean_host} resolves to prohibited address: {ip_str}"
            )

        resolved_ips.append(ip)

    if not resolved_ips:
        raise DNSResolutionError(f"No valid IP addresses resolved for hostname: {clean_host}")

    return tuple(resolved_ips)
