"""Tests for report generation template security, adversarial XSS escaping, and credential sanitization."""

import json
from unittest.mock import MagicMock, patch

import pytest

from app.services.pdf_generator import (
    generate_pdf,
    render_report_html,
    sanitize_target_url_for_report,
)


def test_sanitize_target_url_strips_credentials():
    """Verify that credentials in target URLs are stripped to prevent credential disclosure."""
    url = "https://admin:super_secret_password123@example.com:8443/dashboard?token=foo"
    sanitized = sanitize_target_url_for_report(url)
    assert "super_secret_password123" not in sanitized
    assert "admin" not in sanitized
    assert sanitized == "https://example.com:8443/dashboard?token=foo"


def test_sanitize_target_url_neutralizes_dangerous_schemes():
    """Verify that non-http/https execution schemes are neutralized."""
    js_url = "javascript:alert(document.domain)"
    assert sanitize_target_url_for_report(js_url) == "[blocked-scheme:javascript]"

    data_url = "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
    assert sanitize_target_url_for_report(data_url) == "[blocked-scheme:data]"

    vb_url = "vbscript:msgbox(1)"
    assert sanitize_target_url_for_report(vb_url) == "[blocked-scheme:vbscript]"


def test_sanitize_target_url_handles_raw_hostnames_and_clean_urls():
    """Verify safe URLs and plain hostnames are handled properly."""
    assert sanitize_target_url_for_report("https://example.com/api") == "https://example.com/api"
    assert sanitize_target_url_for_report("http://scan-target.local:8080") == "http://scan-target.local:8080"
    assert sanitize_target_url_for_report("target.example.org") == "target.example.org"
    assert sanitize_target_url_for_report("user:pass@target.example.org") == "target.example.org"
    assert sanitize_target_url_for_report("") == ""


def test_adversarial_xss_in_evidence_escaped():
    """Verify that adversarial XSS payloads in finding evidence are strictly escaped."""
    xss_evidence = "<script>alert('pwned-evidence')</script>"
    payload = {
        "target": "https://example.com",
        "scanned_at": "2026-10-14T00:00:00Z",
        "modules": {
            "headers": {
                "status": "success",
                "findings": [
                    {
                        "code": "XSS_EVIDENCE_TEST",
                        "severity": "critical",
                        "title": "Adversarial Evidence Test",
                        "message": "Testing evidence escaping",
                        "evidence": xss_evidence,
                    }
                ],
            }
        },
    }

    html = render_report_html(
        payload,
        scan_id="xss-test-01",
        target_url="https://example.com",
    )

    # Unescaped tag must NOT appear
    assert "<script>alert('pwned-evidence')</script>" not in html
    # HTML-escaped entity must appear
    assert "&lt;script&gt;alert(&#39;pwned-evidence&#39;)&lt;/script&gt;" in html or \
           "&lt;script&gt;alert('pwned-evidence')&lt;/script&gt;" in html


def test_adversarial_xss_in_target_url_escaped():
    """Verify that adversarial XSS payloads in target URLs are strictly escaped in report HTML."""
    malicious_target = "https://example.com/\"><script>alert('target-xss')</script>"
    payload = {
        "target": malicious_target,
        "scanned_at": "2026-10-14T00:00:00Z",
        "modules": {},
    }

    html = render_report_html(
        payload,
        scan_id="xss-test-02",
        target_url=malicious_target,
    )

    assert "<script>alert('target-xss')</script>" not in html
    assert "&lt;script&gt;alert(" in html


def test_embedded_credentials_in_target_url_not_rendered():
    """Verify embedded credentials in target_url do not leak into the report HTML."""
    creds_url = "https://admin:super_secret_password@example.com/api"
    payload = {
        "target": creds_url,
        "scanned_at": "2026-10-14T00:00:00Z",
        "modules": {},
    }

    html = render_report_html(
        payload,
        scan_id="creds-test-01",
        target_url=creds_url,
    )

    assert "super_secret_password" not in html
    assert "admin:" not in html
    assert "https://example.com/api" in html


def test_adversarial_xss_in_finding_fields_escaped():
    """Verify all finding fields (title, description, message, remediation) are strictly escaped."""
    payload = {
        "target": "https://example.com",
        "scanned_at": "2026-10-14T00:00:00Z",
        "modules": {
            "test_mod": {
                "status": "success",
                "findings": [
                    {
                        "code": "ADV_FINDING",
                        "severity": "high",
                        "title": "<b onmouseover=\"alert('title')\">Malicious Title</b>",
                        "message": "<img src=x onerror=alert('msg')>",
                        "description": "<svg/onload=alert('desc')>",
                        "remediation": "<iframe src=\"http://evil.com\"></iframe>",
                    }
                ],
            }
        },
    }

    html = render_report_html(
        payload,
        scan_id="xss-test-03",
        target_url="https://example.com",
    )

    assert "<b onmouseover" not in html
    assert "<img src=x" not in html
    assert "<svg/onload" not in html
    assert "<iframe src=" not in html

    assert "&lt;b onmouseover=" in html or "&lt;b onmouseover" in html
    assert "&lt;img src=x" in html or "&lt;img src=" in html
    assert "&lt;svg/onload=" in html or "&lt;svg" in html
    assert "&lt;iframe" in html


def test_template_injection_strings_treated_as_literal_text():
    """Verify Jinja template syntax expressions in data are NOT evaluated."""
    payload = {
        "target": "https://example.com",
        "scanned_at": "2026-10-14T00:00:00Z",
        "modules": {
            "test_mod": {
                "status": "success",
                "findings": [
                    {
                        "code": "SSTI_TEST",
                        "severity": "medium",
                        "title": "{{ 7 * 7 }} Template Test",
                        "message": "Message with {{ config }} expression",
                        "evidence": "{% for x in range(5) %}loop{% endfor %}",
                    }
                ],
            }
        },
    }

    html = render_report_html(
        payload,
        scan_id="ssti-test-01",
        target_url="https://example.com",
    )

    # 7 * 7 must NOT evaluate to 49
    assert "{{ 7 * 7 }}" in html or "&#123;&#123; 7 * 7 &#125;&#125;" in html
    assert "{{ config }}" in html or "&#123;&#123; config &#125;&#125;" in html
    # Must not execute loop
    assert "looplooploop" not in html


def test_adversarial_strings_in_technology_and_subdomain_tables():
    """Verify technology fingerprints and subdomain discovery fields are properly escaped."""
    payload = {
        "target": "https://example.com",
        "scanned_at": "2026-10-14T00:00:00Z",
        "modules": {
            "technology": {
                "status": "success",
                "fingerprints": [
                    {
                        "name": "<script>alert('tech-name')</script>",
                        "category": "web_server",
                        "version": "1.0<b onclick=alert(1)>",
                        "confidence": 95,
                    }
                ],
            },
            "subdomain": {
                "status": "success",
                "subdomains": [
                    {
                        "hostname": "\"><svg onload=alert('sd')>.example.com",
                        "source": "<img src=x onerror=alert('src')>",
                        "status": "active",
                    }
                ],
            },
        },
    }

    html = render_report_html(
        payload,
        scan_id="tech-sd-xss-test",
        target_url="https://example.com",
    )

    assert "<script>alert('tech-name')</script>" not in html
    assert "<b onclick=alert(1)>" not in html
    assert "<svg onload=" not in html
    assert "<img src=x onerror=" not in html

    assert "&lt;script&gt;alert(" in html
    assert "&lt;b onclick=" in html or "&lt;b onclick" in html
    assert "&lt;svg onload=" in html or "&lt;svg" in html


def test_module_json_raw_dump_escaped():
    """Verify raw module JSON blocks in <pre> are HTML-escaped."""
    payload = {
        "target": "https://example.com",
        "scanned_at": "2026-10-14T00:00:00Z",
        "modules": {
            "raw_test": {
                "injected_key": "<script>alert('inside-json')</script>",
            }
        },
    }

    html = render_report_html(
        payload,
        scan_id="raw-json-xss-test",
        target_url="https://example.com",
    )

    assert "<script>alert('inside-json')</script>" not in html
    assert "&lt;script&gt;alert" in html


def test_generate_pdf_with_adversarial_payload_executes_safely():
    """Verify generate_pdf compiles safely even with adversarial injection strings."""
    payload = {
        "target": "https://example.com/<script>alert(1)</script>",
        "scanned_at": "2026-10-14T00:00:00Z",
        "modules": {
            "headers": {
                "status": "success",
                "findings": [
                    {
                        "code": "ADV_PDF_TEST",
                        "severity": "critical",
                        "title": "<script>alert('title')</script>",
                        "message": "Message with <b>bold</b> and <script>alert(2)</script>",
                        "evidence": "<img src=x onerror=alert(3)>",
                    }
                ],
            }
        },
    }

    with patch("weasyprint.HTML") as mock_html_cls:
        mock_instance = MagicMock()
        mock_instance.write_pdf.return_value = b"%PDF-1.4 mock sanitized pdf"
        mock_html_cls.return_value = mock_instance

        pdf_bytes = generate_pdf(
            payload,
            scan_id="adv-pdf-01",
            target_url=payload["target"],
        )

        assert pdf_bytes == b"%PDF-1.4 mock sanitized pdf"
        # Verify rendered string passed to HTML does not have raw <script>
        rendered_html = mock_html_cls.call_args[1]["string"]
        assert "<script>alert" not in rendered_html
        assert "<img src=x onerror" not in rendered_html


def test_render_report_html_failed_scan_displays_warning_banner():
    """Verify failed scan reports display prominent warning banner and failure reason."""
    payload = {
        "target": "https://failed.example.com",
        "scanned_at": "2026-10-14T00:00:00Z",
        "modules": {},
    }

    html = render_report_html(
        payload,
        scan_id="failed-scan-01",
        target_url="https://failed.example.com",
        scan_status="FAILED",
        error_message="Host unreachable or connection timed out",
    )

    assert "Scan Status: FAILED" in html
    assert "alert-failed" in html
    assert "must NOT be interpreted as a clean security posture" in html
    assert "Host unreachable or connection timed out" in html


def test_render_report_html_cancelled_scan_displays_warning_banner():
    """Verify cancelled scan reports display prominent warning banner."""
    payload = {
        "target": "https://cancelled.example.com",
        "scanned_at": "2026-10-14T00:00:00Z",
        "modules": {},
    }

    html = render_report_html(
        payload,
        scan_id="cancelled-scan-01",
        target_url="https://cancelled.example.com",
        scan_status="CANCELLED",
        error_message="Scan aborted by operator",
    )

    assert "Scan Status: CANCELLED" in html
    assert "alert-cancelled" in html
    assert "must NOT be interpreted as a clean security posture" in html
    assert "Scan aborted by operator" in html


def test_render_report_html_partial_module_failures_displays_warning():
    """Verify completed scans with partial module failures show warning and badges."""
    payload = {
        "target": "https://partial.example.com",
        "scanned_at": "2026-10-14T00:00:00Z",
        "summary": {
            "module_status": {
                "headers": "success",
                "ssl": "error",
            }
        },
        "modules": {
            "headers": {
                "status": "success",
                "findings": [],
            },
            "ssl": {
                "status": "error",
                "error": "Handshake failure during cipher enumeration",
                "findings": [],
            },
        },
    }

    html = render_report_html(
        payload,
        scan_id="partial-scan-01",
        target_url="https://partial.example.com",
        scan_status="COMPLETED",
    )

    assert "Partial Scan Coverage Warning" in html
    assert "One or more scanner modules encountered errors" in html
    assert "module-badge-error" in html
    assert "Module Error: Handshake failure during cipher enumeration" in html

