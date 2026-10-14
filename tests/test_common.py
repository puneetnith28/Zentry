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


def test_calculate_risk_score_tiers():
    from app.services.common import SCORE_VERSION, calculate_risk_score

    # 1. Minimal Risk (score = 0)
    res_minimal = calculate_risk_score({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
    assert res_minimal.score == 0
    assert res_minimal.level == "Minimal Risk"
    assert res_minimal.version == SCORE_VERSION

    # 2. Low Risk (1 <= score < 25)
    # 2 low (6) + 3 info (3) = 9
    res_low = calculate_risk_score({"low": 2, "info": 3})
    assert res_low.score == 9
    assert res_low.level == "Low Risk"

    # 3. Moderate Risk (25 <= score < 50)
    # 1 high (15) + 2 medium (16) = 31
    res_mod = calculate_risk_score({"high": 1, "medium": 2})
    assert res_mod.score == 31
    assert res_mod.level == "Moderate Risk"

    # 4. High Risk (50 <= score < 75)
    # 4 high (60)
    res_high = calculate_risk_score({"high": 4})
    assert res_high.score == 60
    assert res_high.level == "High Risk"

    # 5. Critical Risk (score >= 75)
    # 3 critical (75)
    res_crit = calculate_risk_score({"critical": 3})
    assert res_crit.score == 75
    assert res_crit.level == "Critical Risk"

    # 6. Upper Bound Capping at 100
    # 10 critical = 250 -> capped at 100
    res_capped = calculate_risk_score({"critical": 10})
    assert res_capped.score == 100
    assert res_capped.level == "Critical Risk"


def test_calculate_risk_score_with_pydantic_model():
    from app.schemas.scan import FindingSummary
    from app.services.common import calculate_risk_score

    summary = FindingSummary(critical=1, high=1, medium=1, low=0, info=0)
    # 25 + 15 + 8 = 48
    result = calculate_risk_score(summary)
    assert result.score == 48
    assert result.level == "Moderate Risk"
    assert result.version == "v1.0"
    d = result.to_dict()
    assert d == {"score": 48, "level": "Moderate Risk", "version": "v1.0"}


def test_calculate_risk_score_empty_and_edge_inputs():
    from app.services.common import calculate_risk_score

    assert calculate_risk_score({}).score == 0
    assert calculate_risk_score({}).level == "Minimal Risk"
    assert calculate_risk_score(None).score == 0
    assert calculate_risk_score("invalid").score == 0


def test_extract_module_statuses_mapping():
    from app.services.common import extract_module_statuses

    modules = {
        "headers": {"status": "success", "findings": []},
        "ssl": {
            "status": "error",
            "error": {"code": "MODULE_TIMEOUT", "message": "Timed out"},
            "findings": [],
        },
        "ports": {
            "status": "error",
            "error": {"code": "POLICY_BLOCKED", "message": "Prohibited destination"},
            "findings": [],
        },
        "tech": {
            "status": "error",
            "error": {"code": "PROHIBITED_IP", "message": "Private IP prohibited"},
            "findings": [],
        },
        "subdomain": {
            "status": "error",
            "error": {"code": "DNS_ERROR", "message": "Resolution error"},
            "findings": [],
        },
        "malformed": "not a dictionary",
    }

    statuses = extract_module_statuses(modules)
    assert statuses == {
        "headers": "SUCCESS",
        "ssl": "TIMEOUT",
        "ports": "BLOCKED",
        "tech": "BLOCKED",
        "subdomain": "ERROR",
        "malformed": "ERROR",
    }


def test_failed_module_not_presented_as_clean():
    """Verify that a module producing 0 findings due to failure is explicitly distinguished from clean status."""
    from app.schemas.scan import FindingSummary, ScanResultPayload
    from app.services.common import extract_module_statuses, summarize_findings

    modules = {
        "ports": {
            "status": "error",
            "error": {"code": "MODULE_TIMEOUT", "message": "Timed out"},
            "findings": [],
        },
        "headers": {
            "status": "success",
            "findings": [],
        },
    }

    summary_counts = summarize_findings(modules)
    statuses = extract_module_statuses(modules)

    # Both modules have 0 findings
    assert summary_counts["critical"] == 0
    assert summary_counts["high"] == 0

    # But module_statuses explicitly distinguishes failure from success
    assert statuses["ports"] == "TIMEOUT"
    assert statuses["headers"] == "SUCCESS"

    summary_model = FindingSummary(**summary_counts, module_statuses=statuses)
    assert summary_model.module_statuses["ports"] == "TIMEOUT"
    assert summary_model.module_statuses["headers"] == "SUCCESS"

    payload = ScanResultPayload(
        target="https://example.com",
        scanned_at="2026-10-14T00:00:00Z",
        modules=modules,
        summary=summary_model,
        module_statuses=statuses,
    )
    assert payload.module_statuses["ports"] == "TIMEOUT"



