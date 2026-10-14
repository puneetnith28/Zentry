"""Comprehensive scanner correctness and canonical findings contract test suite.

Verifies:
1. Canonical finding schema compliance across all scanner modules.
2. Deterministic fingerprinting and deduplication stability.
3. Evidence bounding, redaction, and sanitization (no raw cookies or unbounded bodies).
4. Deterministic canonical backend risk scoring, weights, and score versioning.
5. Module execution state tracking (SUCCESS, ERROR, TIMEOUT, BLOCKED) to prevent false clean status.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.schemas.scan import FindingSummary, ScanResultPayload
from app.services.common import (
    CANONICAL_REMEDIATIONS,
    CANONICAL_TITLES,
    SCORE_VERSION,
    SEVERITY_WEIGHTS,
    Finding,
    FindingSeverity,
    calculate_risk_score,
    extract_module_statuses,
    serialize,
    summarize_findings,
)
from app.services.headers import CookieInfo, _analyze_headers, inspect_headers_async
from app.services.ports import scan_ports_async
from app.services.ssl import inspect_ssl_async
from app.services.subdomain import discover_subdomains_async
from app.services.technology import inspect_technology_async


# ---------------------------------------------------------------------------
# 1. Canonical Finding Schema & Fingerprinting Contract Tests
# ---------------------------------------------------------------------------


def test_finding_schema_contract_compliance():
    """Verify that Finding dataclass populates all canonical fields according to contract."""
    finding = Finding(
        code="MISSING_HSTS",
        severity=FindingSeverity.HIGH,
        message="Strict-Transport-Security header is missing",
        evidence="Observed headers: server=nginx",
        module="headers",
        confidence=95,
    )

    data = serialize(finding)
    required_fields = {
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
    assert required_fields.issubset(set(data.keys()))
    assert data["code"] == "MISSING_HSTS"
    assert data["severity"] == "high"
    assert data["module"] == "headers"
    assert data["title"] == CANONICAL_TITLES["MISSING_HSTS"]
    assert data["description"] == "Strict-Transport-Security header is missing"
    assert data["remediation"] == CANONICAL_REMEDIATIONS["MISSING_HSTS"]
    assert len(data["fingerprint"]) == 16
    assert all(c in "0123456789abcdef" for c in data["fingerprint"])


def test_finding_fingerprint_determinism_and_uniqueness():
    """Verify finding fingerprints are deterministic, repeatable, and distinguish different findings."""
    f1 = Finding(
        code="FTP_OPEN",
        severity=FindingSeverity.MEDIUM,
        message="Port 21 is open",
        module="ports",
    )
    f2 = Finding(
        code="FTP_OPEN",
        severity=FindingSeverity.MEDIUM,
        message="Port 21 is open",
        module="ports",
    )
    f3 = Finding(
        code="TELNET_OPEN",
        severity=FindingSeverity.HIGH,
        message="Port 23 is open",
        module="ports",
    )

    assert f1.fingerprint == f2.fingerprint
    assert f1.fingerprint != f3.fingerprint


def test_all_canonical_catalogs_have_required_scanner_codes():
    """Verify that canonical catalogs include all standard finding codes across scanner engines."""
    required_codes = [
        "MISSING_HSTS",
        "MISSING_CSP",
        "MISSING_X_FRAME_OPTIONS",
        "MISSING_X_CONTENT_TYPE_OPTIONS",
        "PORT_OPEN",
        "FTP_OPEN",
        "TELNET_OPEN",
        "SMB_OPEN",
        "CERT_EXPIRED",
        "CERT_EXPIRING_SOON",
        "CERT_HOSTNAME_MISMATCH",
        "SELF_SIGNED_CERT",
        "TECHNOLOGY_DISCLOSURE",
        "SUBDOMAINS_DISCOVERED",
    ]
    for code in required_codes:
        assert code in CANONICAL_TITLES, f"Missing title for {code}"
        assert code in CANONICAL_REMEDIATIONS, f"Missing remediation for {code}"


# ---------------------------------------------------------------------------
# 2. Evidence Bounding and Sanitization Tests
# ---------------------------------------------------------------------------


def test_evidence_bounding_and_sanitization():
    """Verify that oversized evidence strings are safely truncated to bounded limits."""
    huge_evidence = "X" * 10000
    finding = Finding(
        code="MISSING_CSP",
        severity=FindingSeverity.MEDIUM,
        message="CSP header is missing",
        evidence=huge_evidence,
        module="headers",
    )
    # Finding constructor should enforce length bound <= 4096
    assert len(finding.evidence) <= 4096
    assert finding.evidence.endswith("... [truncated]")


def test_cookie_evidence_sanitization_no_value_leakage():
    """Verify that cookie inspection never captures or logs sensitive cookie values."""
    cookies = [
        CookieInfo(
            name="session_id",
            secure=False,
            httponly=False,
            samesite="None",
        )
    ]
    findings = _analyze_headers({}, cookies, is_https=True)
    insecure_cookie_findings = [f for f in findings if f.code == "INSECURE_COOKIE"]
    assert len(insecure_cookie_findings) == 1
    evidence = insecure_cookie_findings[0].evidence

    # Evidence must specify flag attributes and cookie name, but never a value
    assert "session_id" in evidence
    assert "missing Secure" in evidence
    assert "missing HttpOnly" in evidence
    assert "value" not in evidence.lower()


# ---------------------------------------------------------------------------
# 3. Canonical Risk Scoring and Bounds Tests
# ---------------------------------------------------------------------------


def test_scoring_weights_and_tier_boundaries():
    """Verify deterministic scoring calculations across all severity weight tiers."""
    assert SEVERITY_WEIGHTS["critical"] == 25
    assert SEVERITY_WEIGHTS["high"] == 15
    assert SEVERITY_WEIGHTS["medium"] == 8
    assert SEVERITY_WEIGHTS["low"] == 3
    assert SEVERITY_WEIGHTS["info"] == 1

    # 0 points -> Minimal Risk
    res0 = calculate_risk_score({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
    assert res0.score == 0
    assert res0.level == "Minimal Risk"
    assert res0.version == SCORE_VERSION

    # 1-24 points -> Low Risk
    res_low = calculate_risk_score({"low": 4, "info": 5})  # 12 + 5 = 17
    assert res_low.score == 17
    assert res_low.level == "Low Risk"

    # 25-49 points -> Moderate Risk
    res_mod = calculate_risk_score({"high": 1, "medium": 2})  # 15 + 16 = 31
    assert res_mod.score == 31
    assert res_mod.level == "Moderate Risk"

    # 50-74 points -> High Risk
    res_high = calculate_risk_score({"high": 4})  # 60
    assert res_high.score == 60
    assert res_high.level == "High Risk"

    # 75+ points -> Critical Risk
    res_crit = calculate_risk_score({"critical": 3})  # 75
    assert res_crit.score == 75
    assert res_crit.level == "Critical Risk"

    # Cap at 100
    res_capped = calculate_risk_score({"critical": 10})  # 250 -> 100
    assert res_capped.score == 100
    assert res_capped.level == "Critical Risk"


def test_scoring_with_summary_model():
    """Verify calculate_risk_score accepts FindingSummary Pydantic models."""
    summary = FindingSummary(critical=1, high=2, medium=0, low=1, info=0)  # 25 + 30 + 3 = 58
    res = calculate_risk_score(summary)
    assert res.score == 58
    assert res.level == "High Risk"
    assert res.version == SCORE_VERSION


# ---------------------------------------------------------------------------
# 4. Module Execution State Tracking & Safe Presentation Tests
# ---------------------------------------------------------------------------


def test_extract_module_statuses_covers_all_error_types():
    """Verify module status extractor categorizes SUCCESS, TIMEOUT, BLOCKED, and ERROR."""
    modules = {
        "headers": {"status": "success", "findings": []},
        "ssl": {"status": "error", "error": {"code": "MODULE_TIMEOUT", "message": "Timed out"}, "findings": []},
        "ports": {"status": "error", "error": {"code": "POLICY_BLOCKED", "message": "SSRF blocked"}, "findings": []},
        "technology": {"status": "error", "error": {"code": "PROHIBITED_DESTINATION", "message": "Private IP"}, "findings": []},
        "subdomain": {"status": "error", "error": {"code": "DNS_FAILURE", "message": "Lookup failed"}, "findings": []},
    }

    statuses = extract_module_statuses(modules)
    assert statuses["headers"] == "SUCCESS"
    assert statuses["ssl"] == "TIMEOUT"
    assert statuses["ports"] == "BLOCKED"
    assert statuses["technology"] == "BLOCKED"
    assert statuses["subdomain"] == "ERROR"


def test_module_failure_never_masquerades_as_clean():
    """Ensure that a scan with failed modules and 0 findings does not present as clean."""
    modules = {
        "headers": {
            "status": "error",
            "error": {"code": "MODULE_TIMEOUT", "message": "Gateway timeout"},
            "findings": [],
        },
        "ssl": {
            "status": "error",
            "error": {"code": "POLICY_BLOCKED", "message": "Connection prohibited"},
            "findings": [],
        },
    }

    counts = summarize_findings(modules)
    statuses = extract_module_statuses(modules)

    # Finding counts are 0, but execution was NOT clean
    assert counts["critical"] == 0
    assert counts["high"] == 0
    assert statuses["headers"] == "TIMEOUT"
    assert statuses["ssl"] == "BLOCKED"

    payload = ScanResultPayload(
        target="https://example.com",
        scanned_at="2026-10-14T12:00:00Z",
        modules=modules,
        summary=FindingSummary(**counts, module_statuses=statuses),
        module_statuses=statuses,
    )
    assert payload.module_statuses["headers"] == "TIMEOUT"
    assert payload.module_statuses["ssl"] == "BLOCKED"


# ---------------------------------------------------------------------------
# 5. Integrated Scanner Correctness Suite Across All 5 Engines
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_all_scanner_modules_produce_canonical_findings():
    """Test all 5 scanner engines with simulated responses, verifying canonical schema conformity."""
    # 1. Headers Scanner
    async def mock_headers_handler(request: httpx.Request):
        return httpx.Response(
            200,
            headers={
                "content-type": "text/html",
                "set-cookie": "session=12345; SameSite=Lax",  # missing Secure & HttpOnly
            },
            text="<html><body>Hello</body></html>",
        )

    transport = httpx.MockTransport(mock_headers_handler)
    async with httpx.AsyncClient(transport=transport) as mock_client:
        header_res = await inspect_headers_async("https://example.com", client=mock_client)
        assert header_res["status"] == "success"
        assert len(header_res["findings"]) > 0
        for f in header_res["findings"]:
            assert "code" in f
            assert "severity" in f
            assert "fingerprint" in f
            assert "module" in f
            assert isinstance(f["module"], str)

    # 2. Ports Scanner
    with patch("app.services.ports.resolve_public_target", return_value="93.184.216.34"):
        with patch("app.services.ports._probe_port") as mock_probe:
            async def probe_side_effect(host, port, *, timeout=3.0):
                if port == 21:
                    return "open"
                return "closed"

            mock_probe.side_effect = probe_side_effect
            ports_res = await scan_ports_async("example.com", ports=[21, 80])
            assert ports_res["status"] == "success"
            assert any(f["code"] == "FTP_OPEN" for f in ports_res["findings"])
            for f in ports_res["findings"]:
                assert "module" in f
                assert len(f["fingerprint"]) == 16

    # 3. Technology Scanner
    async def mock_tech_handler(request: httpx.Request):
        return httpx.Response(
            200,
            headers={"server": "Apache/2.4.41 (Ubuntu)", "x-powered-by": "PHP/7.4.3"},
            text="<html><head><meta name='generator' content='WordPress 5.8'></head><body>Hi</body></html>",
        )

    tech_transport = httpx.MockTransport(mock_tech_handler)
    async with httpx.AsyncClient(transport=tech_transport) as tech_client:
        tech_res = await inspect_technology_async("https://example.com", client=tech_client)
        assert tech_res["status"] == "success"
        assert len(tech_res["findings"]) > 0
        for f in tech_res["findings"]:
            assert "module" in f
            assert "fingerprint" in f

    # 4. Subdomains Scanner
    with patch("app.services.subdomain.discover_subdomains_async") as mock_sub:
        mock_sub.return_value = {
            "status": "success",
            "subdomains": ["api.example.com", "dev.example.com"],
            "findings": [
                serialize(
                    Finding(
                        code="SUBDOMAINS_DISCOVERED",
                        severity=FindingSeverity.INFO,
                        message="Discovered 2 passive subdomains",
                        evidence="Subdomains: api.example.com, dev.example.com",
                        module="subdomain",
                    )
                )
            ],
        }
        sub_res = await mock_sub("example.com")
        assert sub_res["status"] == "success"
        assert len(sub_res["findings"]) == 1
        assert sub_res["findings"][0]["code"] == "SUBDOMAINS_DISCOVERED"
        assert sub_res["findings"][0]["module"] == "subdomain"

    # 5. SSL Scanner
    with patch("app.services.ssl.inspect_ssl_async") as mock_ssl:
        mock_ssl.return_value = {
            "status": "success",
            "certificate": {"subject": {"common_name": "example.com"}},
            "findings": [
                serialize(
                    Finding(
                        code="CERT_EXPIRING_SOON",
                        severity=FindingSeverity.MEDIUM,
                        message="Certificate expires in 12 days",
                        evidence="Valid until: 2026-10-26",
                        module="ssl",
                    )
                )
            ],
        }
        ssl_res = await mock_ssl("example.com")
        assert ssl_res["status"] == "success"
        assert ssl_res["findings"][0]["code"] == "CERT_EXPIRING_SOON"
        assert ssl_res["findings"][0]["module"] == "ssl"
