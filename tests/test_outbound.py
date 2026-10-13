import pytest
from app.core.outbound import (
    ProhibitedDestinationError,
    is_prohibited_ip,
    validate_ip_destination,
)


@pytest.mark.parametrize(
    "public_ip",
    [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "142.250.190.46",
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
        "::ffff:8.8.8.8",  # Public IPv4 mapped to IPv6
    ],
)
def test_public_ips_permitted(public_ip: str):
    assert not is_prohibited_ip(public_ip)
    validated = validate_ip_destination(public_ip)
    assert validated is not None


@pytest.mark.parametrize(
    "prohibited_ip",
    [
        # Loopback
        "127.0.0.1",
        "127.0.0.254",
        "127.1.2.3",
        "::1",
        "::ffff:127.0.0.1",
        # Private RFC 1918
        "10.0.0.1",
        "10.255.255.254",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.0.1",
        "192.168.100.200",
        "::ffff:10.0.0.1",
        "::ffff:192.168.1.1",
        # Link-local / Cloud Metadata
        "169.254.169.254",
        "169.254.1.1",
        "fe80::1",
        "fe80::dead:beef",
        "::ffff:169.254.169.254",
        # CGNAT RFC 6598
        "100.64.0.1",
        "100.127.255.254",
        # Documentation & Testnet
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "2001:db8::1",
        # Multicast & Broadcast
        "224.0.0.1",
        "239.255.255.250",
        "ff02::1",
        "255.255.255.255",
        # Current / Unspecified
        "0.0.0.0",
        "::",
        # IPv6 ULA
        "fc00::1",
        "fd00:1234::1",
    ],
)
def test_prohibited_ips_blocked(prohibited_ip: str):
    assert is_prohibited_ip(prohibited_ip)
    with pytest.raises(ProhibitedDestinationError):
        validate_ip_destination(prohibited_ip)


def test_invalid_ip_representation_rejected():
    assert is_prohibited_ip("not-an-ip")
    with pytest.raises(ProhibitedDestinationError):
        validate_ip_destination("not-an-ip")
