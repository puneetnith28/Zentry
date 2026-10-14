from app.services.common import (
    CANONICAL_REMEDIATIONS,
    CANONICAL_TITLES,
    Finding,
    FindingSeverity,
    serialize,
    summarize_findings,
)


def test_summarize_findings_counts_severities():
    modules = {
        "ssl": {
            "findings": [
                {"severity": "critical", "code": "A"},
                {"severity": "high", "code": "B"},
            ]
        },
        "headers": {
            "findings": [{"severity": "medium", "code": "C"}],
        },
    }
    summary = summarize_findings(modules)
    assert summary["critical"] == 1
    assert summary["high"] == 1
    assert summary["medium"] == 1
    assert summary["low"] == 0
    assert summary["info"] == 0


def test_finding_canonical_schema_defaults():
    finding = Finding(
        code="MISSING_HSTS",
        severity=FindingSeverity.HIGH,
        message="Strict-Transport-Security header is missing",
    )
    assert finding.code == "MISSING_HSTS"
    assert finding.severity == FindingSeverity.HIGH
    assert finding.message == "Strict-Transport-Security header is missing"
    assert finding.title == "Missing Strict-Transport-Security (HSTS)"
    assert finding.description == "Strict-Transport-Security header is missing"
    assert finding.evidence == "Strict-Transport-Security header is missing"
    assert "max-age=31536000" in finding.remediation
    assert len(finding.fingerprint) == 16
    assert finding.confidence == 100
    assert finding.module == ""


def test_finding_custom_overrides():
    finding = Finding(
        code="CUSTOM_CODE",
        severity=FindingSeverity.MEDIUM,
        message="A custom message",
        title="Custom Title",
        description="Detailed custom description",
        evidence="Found header foo=bar",
        remediation="Remove header foo",
        fingerprint="custom_fp_123456",
        confidence=85,
        module="custom_module",
    )
    assert finding.code == "CUSTOM_CODE"
    assert finding.title == "Custom Title"
    assert finding.description == "Detailed custom description"
    assert finding.evidence == "Found header foo=bar"
    assert finding.remediation == "Remove header foo"
    assert finding.fingerprint == "custom_fp_123456"
    assert finding.confidence == 85
    assert finding.module == "custom_module"


def test_finding_serialization():
    finding = Finding(
        code="FTP_OPEN",
        severity=FindingSeverity.MEDIUM,
        message="Potentially risky port 21/tcp is open",
        module="ports",
    )
    serialized = serialize(finding)
    assert isinstance(serialized, dict)
    expected_keys = {
        "code",
        "severity",
        "message",
        "title",
        "description",
        "evidence",
        "remediation",
        "fingerprint",
        "confidence",
        "module",
    }
    assert expected_keys.issubset(set(serialized.keys()))
    assert serialized["code"] == "FTP_OPEN"
    assert serialized["severity"] == "medium"
    assert serialized["title"] == "Open FTP Service (Port 21)"
    assert "Disable unencrypted FTP" in serialized["remediation"]
    assert serialized["module"] == "ports"


def test_finding_fingerprint_deterministic_and_unique():
    f1 = Finding(
        code="TELNET_OPEN",
        severity=FindingSeverity.HIGH,
        message="Port 23 open",
        module="ports",
    )
    f2 = Finding(
        code="TELNET_OPEN",
        severity=FindingSeverity.HIGH,
        message="Port 23 open",
        module="ports",
    )
    f3 = Finding(
        code="TELNET_OPEN",
        severity=FindingSeverity.HIGH,
        message="Port 23 open on different host",
        module="ports",
    )
    assert f1.fingerprint == f2.fingerprint
    assert f1.fingerprint != f3.fingerprint


def test_canonical_catalogs_have_major_scanner_codes():
    major_codes = [
        "MISSING_HSTS",
        "MISSING_CSP",
        "MISSING_X_FRAME_OPTIONS",
        "COOKIE_MISSING_SECURE",
        "FTP_OPEN",
        "CERT_EXPIRED",
        "TECHNOLOGY_DISCLOSURE",
        "SUBDOMAINS_DISCOVERED",
    ]
    for code in major_codes:
        assert code in CANONICAL_TITLES
        assert code in CANONICAL_REMEDIATIONS

