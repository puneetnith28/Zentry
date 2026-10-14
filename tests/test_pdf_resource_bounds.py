"""Tests for PDF report generation resource bounds, finding limits, and timeout enforcement."""

import time
from unittest.mock import MagicMock, patch

import pytest

from app.services.pdf_generator import (
    DEFAULT_MAX_FINDINGS,
    PDFGenerationTimeoutError,
    generate_pdf,
    render_report_html,
)


def test_render_report_html_bounds_findings_count():
    """Verify that report rendering bounds the total number of rendered findings to max_findings."""
    findings = []
    # 5 critical, 20 high, 40 medium, 60 low = 125 findings
    for i in range(5):
        findings.append({"code": f"CRIT_{i}", "severity": "critical", "title": f"Critical Issue {i}", "message": f"Critical msg {i}"})
    for i in range(20):
        findings.append({"code": f"HIGH_{i}", "severity": "high", "title": f"High Issue {i}", "message": f"High msg {i}"})
    for i in range(40):
        findings.append({"code": f"MED_{i}", "severity": "medium", "title": f"Medium Issue {i}", "message": f"Medium msg {i}"})
    for i in range(60):
        findings.append({"code": f"LOW_{i}", "severity": "low", "title": f"Low Issue {i}", "message": f"Low msg {i}"})

    payload = {
        "target": "https://example.com",
        "scanned_at": "2026-10-14T00:00:00Z",
        "modules": {
            "test_module": {"status": "success", "findings": findings}
        },
    }

    html = render_report_html(
        payload,
        scan_id="test-scan-123",
        target_url="https://example.com",
        max_findings=50,
    )

    # Must contain truncation note
    assert "Displaying top 50 most critical findings" in html
    assert "out of 125 total recorded findings" in html

    # All 5 critical and 20 high findings must be present (25 total), plus 25 of the medium findings
    for i in range(5):
        assert f"CRIT_{i}" in html
    for i in range(20):
        assert f"HIGH_{i}" in html


def test_render_report_html_bounds_evidence_length():
    """Verify oversized evidence in findings is bounded and truncated."""
    huge_evidence = "EVIDENCE_" + ("A" * 5000)
    payload = {
        "target": "https://example.com",
        "scanned_at": "2026-10-14T00:00:00Z",
        "modules": {
            "test_module": {
                "status": "success",
                "findings": [
                    {
                        "code": "TEST_EVIDENCE",
                        "severity": "high",
                        "title": "Evidence Test",
                        "message": "Message with huge evidence",
                        "evidence": huge_evidence,
                    }
                ],
            }
        },
    }

    html = render_report_html(
        payload,
        scan_id="test-scan-456",
        target_url="https://example.com",
    )

    # Should not contain the full 5000-char string
    assert huge_evidence not in html
    assert "EVIDENCE_" in html


def test_generate_pdf_timeout_enforcement():
    """Verify PDF generation raises PDFGenerationTimeoutError when compilation budget is exceeded."""
    def mock_slow_write_pdf(*args, **kwargs):
        time.sleep(0.5)
        return b"%PDF-dummy"

    payload = {
        "target": "https://example.com",
        "scanned_at": "2026-10-14T00:00:00Z",
        "modules": {},
    }

    with patch("weasyprint.HTML") as mock_html_cls:
        mock_instance = MagicMock()
        mock_instance.write_pdf.side_effect = mock_slow_write_pdf
        mock_html_cls.return_value = mock_instance

        with pytest.raises(PDFGenerationTimeoutError, match="exceeded maximum execution budget"):
            generate_pdf(
                payload,
                scan_id="test-scan-789",
                target_url="https://example.com",
                timeout=0.05,
            )
