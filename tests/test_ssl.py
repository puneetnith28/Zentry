import pytest

from app.services.ssl import _parse_target


@pytest.mark.parametrize(
    ("target", "port", "expected_host", "expected_port"),
    [
        ("example.com", None, "example.com", 443),
        ("example.com:8443", None, "example.com", 8443),
        ("https://example.com/path", None, "example.com", 443),
        ("https://example.com:8443", None, "example.com", 8443),
    ],
)
def test_parse_target(target, port, expected_host, expected_port):
    host, resolved = _parse_target(target, port)
    assert host == expected_host
    assert resolved == expected_port


@pytest.mark.asyncio
async def test_inspect_ssl_blocks_prohibited_destination():
    from app.services.ssl import inspect_ssl_async

    result = await inspect_ssl_async("127.0.0.1")
    assert result["status"] == "error"
    assert result["error"]["code"] == "PROHIBITED_DESTINATION"


def _create_test_cert(
    common_name="example.com",
    san_dns=None,
    san_ips=None,
    days_valid=30,
    key=None,
    include_san_ext=True,
    sig_hash=None,
):
    from datetime import datetime, timedelta, timezone
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    start_days_ago = abs(days_valid) + 10 if days_valid < 0 else 1
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=start_days_ago))
        .not_valid_after(now + timedelta(days=days_valid))
    )
    if include_san_ext and (san_dns is not None or san_ips is not None):
        general_names = []
        for d in (san_dns or []):
            general_names.append(x509.DNSName(d))
        for ip_str in (san_ips or []):
            general_names.append(x509.IPAddress(ipaddress.ip_address(ip_str)))
        builder = builder.add_extension(
            x509.SubjectAlternativeName(general_names),
            critical=False,
        )
    return builder.sign(key, sig_hash or hashes.SHA256())


def test_rfc6125_strict_wildcard_matching():
    from app.services.ssl import _match_wildcard

    # Exact match
    assert _match_wildcard("api.example.com", "api.example.com") is True
    assert _match_wildcard("API.EXAMPLE.COM", "api.example.com") is True

    # Valid single-label wildcard match
    assert _match_wildcard("api.example.com", "*.example.com") is True
    assert _match_wildcard("web.example.com", "*.example.com") is True

    # Multi-label subdomains PROHIBITED by RFC 6125
    assert _match_wildcard("sub.api.example.com", "*.example.com") is False
    assert _match_wildcard("deep.sub.api.example.com", "*.example.com") is False

    # Apex domain match PROHIBITED by RFC 6125
    assert _match_wildcard("example.com", "*.example.com") is False

    # TLD wildcards PROHIBITED
    assert _match_wildcard("example.com", "*.com") is False
    assert _match_wildcard("com", "*") is False

    # Non-leftmost wildcards PROHIBITED
    assert _match_wildcard("sub.api.example.com", "sub.*.example.com") is False

    # Partial / embedded label wildcards PROHIBITED
    assert _match_wildcard("api1.example.com", "api*.example.com") is False
    assert _match_wildcard("1api.example.com", "*api.example.com") is False

    # IP addresses cannot match wildcard patterns
    assert _match_wildcard("192.168.1.1", "*.168.1.1") is False


def test_rfc6125_san_precedence_over_cn():
    from app.services.ssl import _hostname_matches_cert

    # Certificate has SAN DNS ["service.example.com"] and Subject CN "legacy.example.com"
    cert = _create_test_cert(
        common_name="legacy.example.com",
        san_dns=["service.example.com"],
        include_san_ext=True,
    )

    # Must match the SAN DNS
    assert _hostname_matches_cert("service.example.com", cert) is True

    # Must NOT match the CN because SAN is present and has absolute precedence
    assert _hostname_matches_cert("legacy.example.com", cert) is False


def test_rfc6125_cn_fallback_when_san_absent():
    from app.services.ssl import _hostname_matches_cert

    # Certificate has NO SAN extension and Subject CN "legacy.example.com"
    cert = _create_test_cert(
        common_name="legacy.example.com",
        include_san_ext=False,
    )

    # Falls back to CN
    assert _hostname_matches_cert("legacy.example.com", cert) is True
    assert _hostname_matches_cert("other.example.com", cert) is False


def test_rfc6125_san_ip_matching():
    from app.services.ssl import _hostname_matches_cert

    cert = _create_test_cert(
        common_name="internal-node",
        san_ips=["198.51.100.25"],
        include_san_ext=True,
    )

    assert _hostname_matches_cert("198.51.100.25", cert) is True
    assert _hostname_matches_cert("198.51.100.26", cert) is False


def test_derive_findings_expired_and_chain_expired():
    from app.services.ssl import (
        _derive_findings,
        _parse_certificate,
        TlsInfo,
        ValidationResult,
    )

    leaf_expired = _create_test_cert(common_name="leaf.example.com", days_valid=-5)
    cert_details = _parse_certificate(leaf_expired, expiring_soon_days=30)
    tls_info = TlsInfo(
        version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        cipher_protocol="TLSv1.3",
    )
    val = ValidationResult(trusted=True, hostname_match=True, errors=[], warnings=[])

    findings = _derive_findings(
        cert_details,
        tls_info,
        val,
        expected_host="leaf.example.com",
        expiring_soon_days=30,
        chain_certs=[leaf_expired],
    )
    codes = [f.code for f in findings]
    assert "CERT_EXPIRED" in codes

    # Valid leaf but expired intermediate in chain
    leaf_valid = _create_test_cert(common_name="leaf.example.com", days_valid=90)
    inter_expired = _create_test_cert(common_name="intermediate-ca.example.com", days_valid=-10)
    leaf_details = _parse_certificate(leaf_valid, expiring_soon_days=30)

    chain_findings = _derive_findings(
        leaf_details,
        tls_info,
        val,
        expected_host="leaf.example.com",
        expiring_soon_days=30,
        chain_certs=[leaf_valid, inter_expired],
    )
    chain_codes = [f.code for f in chain_findings]
    assert "CHAIN_CERT_EXPIRED" in chain_codes

