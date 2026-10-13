import pytest
from app.core.outbound import (
    DNSResolutionError,
    ProhibitedDestinationError,
    is_prohibited_ip,
    resolve_public_target,
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


def test_resolve_public_target_ip_literal():
    ips = resolve_public_target("93.184.216.34")
    assert len(ips) == 1
    assert str(ips[0]) == "93.184.216.34"

    with pytest.raises(ProhibitedDestinationError):
        resolve_public_target("127.0.0.1")


def test_resolve_public_target_success(monkeypatch):
    fake_addrinfo = [
        (2, 1, 6, "", ("93.184.216.34", 443)),
        (10, 1, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 443)),
    ]
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: fake_addrinfo)

    ips = resolve_public_target("example.com", 443)
    assert len(ips) == 2
    assert str(ips[0]) == "93.184.216.34"
    assert str(ips[1]) == "2606:2800:220:1:248:1893:25c8:1946"


def test_resolve_public_target_private_blocked(monkeypatch):
    fake_addrinfo = [
        (2, 1, 6, "", ("10.0.0.1", 443)),
    ]
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: fake_addrinfo)

    with pytest.raises(ProhibitedDestinationError) as exc:
        resolve_public_target("internal.corp", 443)
    assert "resolves to prohibited address" in str(exc.value)


def test_resolve_public_target_mixed_answers_blocked(monkeypatch):
    """If DNS returns both public and private addresses, the target MUST be rejected."""
    fake_addrinfo = [
        (2, 1, 6, "", ("93.184.216.34", 443)),
        (2, 1, 6, "", ("192.168.1.1", 443)),
    ]
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: fake_addrinfo)

    with pytest.raises(ProhibitedDestinationError) as exc:
        resolve_public_target("rebinding-test.com", 443)
    assert "resolves to prohibited address: 192.168.1.1" in str(exc.value)


def test_resolve_public_target_gaierror(monkeypatch):
    def fake_gaierror(*args, **kwargs):
        import socket
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr("socket.getaddrinfo", fake_gaierror)

    from app.core.outbound import DNSResolutionError
    with pytest.raises(DNSResolutionError) as exc:
        resolve_public_target("nonexistent.invalid", 80)
    assert "Unable to resolve hostname" in str(exc.value)


def test_resolve_public_target_empty_hostname():
    from app.core.outbound import DNSResolutionError
    with pytest.raises(DNSResolutionError):
        resolve_public_target("   ")
