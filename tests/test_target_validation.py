import pytest

from app.core.target_validation import TargetValidationError, validate_scan_target


def test_validate_normalizes_https():
    result = validate_scan_target("example.com", block_private=False)
    assert result == "https://example.com"


def test_validate_lowercases_hostname():
    result = validate_scan_target("HTTPS://EXAMPLE.COM/PATH", block_private=False)
    assert result == "https://example.com/PATH"


def test_validate_rejects_embedded_credentials():
    with pytest.raises(TargetValidationError, match="Embedded credentials"):
        validate_scan_target("https://admin:secret@example.com", block_private=False)

    with pytest.raises(TargetValidationError, match="Embedded credentials"):
        validate_scan_target("user@example.com", block_private=False)


def test_validate_valid_custom_ports():
    result = validate_scan_target("https://example.com:8443", block_private=False)
    assert result == "https://example.com:8443"


def test_validate_rejects_invalid_ports():
    with pytest.raises(TargetValidationError, match="Invalid port number"):
        validate_scan_target("https://example.com:0", block_private=False)

    with pytest.raises(TargetValidationError, match="Invalid port number"):
        validate_scan_target("https://example.com:70000", block_private=False)


def test_validate_rejects_private_ip():
    with pytest.raises(TargetValidationError, match="Scanning private or loopback"):
        validate_scan_target("https://127.0.0.1", block_private=True)


def test_validate_rejects_invalid_scheme():
    with pytest.raises(TargetValidationError, match="http or https scheme"):
        validate_scan_target("ftp://example.com", block_private=False)

    with pytest.raises(TargetValidationError, match="http or https scheme"):
        validate_scan_target("file:///etc/passwd", block_private=False)


def test_validate_rejects_empty_or_whitespace():
    with pytest.raises(TargetValidationError, match="Target URL is required"):
        validate_scan_target("", block_private=False)

    with pytest.raises(TargetValidationError, match="Target URL is required"):
        validate_scan_target("   ", block_private=False)
