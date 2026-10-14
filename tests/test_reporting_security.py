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


def test_render_report_html_renders_precomputed_score_identically():
    """Verify PDF generator reads precomputed canonical score directly from result_payload."""
    payload = {
        "target": "https://scored.example.com",
        "scanned_at": "2026-10-14T12:00:00Z",
        "risk_score": 75,
        "risk_level": "Critical Risk",
        "score_version": "1.0.0",
        "summary": {"critical": 3, "high": 0, "medium": 0, "low": 0, "info": 0},
        "modules": {},
    }

    html = render_report_html(
        payload,
        scan_id="score-test-01",
        target_url="https://scored.example.com",
    )

    assert "75/100" in html
    assert "Critical Risk" in html
    assert "v1.0.0" in html


def test_render_report_html_fallback_score_calculation():
    """Verify fallback score calculation matches canonical calculate_risk_score output."""
    payload = {
        "target": "https://fallback.example.com",
        "scanned_at": "2026-10-14T12:00:00Z",
        # No risk_score provided; must be calculated from summary
        "summary": {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0},  # 25 + 30 = 55
        "modules": {},
    }

    html = render_report_html(
        payload,
        scan_id="score-test-02",
        target_url="https://fallback.example.com",
    )

    assert "55/100" in html
    assert "High Risk" in html
    assert "v1.0" in html


def test_render_report_html_renders_finding_fingerprints():
    """Verify finding deterministic fingerprints (IDs) are rendered in the findings table."""
    payload = {
        "target": "https://fp.example.com",
        "scanned_at": "2026-10-14T12:00:00Z",
        "modules": {
            "headers": {
                "status": "success",
                "findings": [
                    {
                        "code": "MISSING_CSP",
                        "severity": "high",
                        "title": "Missing Content-Security-Policy",
                        "message": "CSP header is not set",
                        "fingerprint": "a1b2c3d4e5f67890",
                    }
                ],
            }
        },
    }

    html = render_report_html(
        payload,
        scan_id="fp-test-01",
        target_url="https://fp.example.com",
    )

    assert "ID: a1b2c3d4e5f6" in html
    assert "MISSING_CSP" in html
    assert "Missing Content-Security-Policy" in html


def test_api_json_and_report_data_contract_alignment(client, db_session):
    """Contract test verifying 100% parity between API JSON response and report data."""
    import uuid
    from app.core.security import create_access_token, get_password_hash
    from app.db.models import ScanJob, ScanStatusEnum, User

    user = User(
        email=f"contract_{uuid.uuid4().hex[:8]}@example.com",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_access_token({"sub": str(user.id)})
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "target": "https://contract.example.com",
        "scanned_at": "2026-10-14T15:30:00+00:00",
        "risk_score": 60,
        "risk_level": "High Risk",
        "score_version": "1.0.0",
        "summary": {
            "critical": 0,
            "high": 4,
            "medium": 0,
            "low": 0,
            "info": 0,
        },
        "modules": {
            "headers": {
                "status": "success",
                "findings": [
                    {
                        "code": "MISSING_HSTS",
                        "severity": "high",
                        "title": "Missing Strict-Transport-Security (HSTS)",
                        "message": "HSTS header is absent",
                        "fingerprint": "f00ba41234567890",
                    }
                ],
            }
        },
    }

    job = ScanJob(
        user_id=user.id,
        target_url="https://contract.example.com",
        status=ScanStatusEnum.COMPLETED,
        result_payload=payload,
    )
    db_session.add(job)
    db_session.commit()
    db_session.refresh(job)

    # 1. Fetch API JSON representation
    api_resp = client.get(f"/api/v1/scans/{job.id}", headers=headers)
    assert api_resp.status_code == 200
    api_data = api_resp.json()

    api_result = api_data["result"]
    assert api_result["risk_score"] == 60
    assert api_result["risk_level"] == "High Risk"
    assert api_result["score_version"] == "1.0.0"
    assert api_result["scanned_at"] == "2026-10-14T15:30:00+00:00"

    # 2. Render report HTML representation
    report_html = render_report_html(
        job.result_payload,
        scan_id=str(job.id),
        target_url=job.target_url,
    )

    # 3. Assert zero divergence in contract fields
    assert f"{api_result['risk_score']}/100" in report_html
    assert api_result["risk_level"] in report_html
    assert f"v{api_result['score_version']}" in report_html
    assert api_result["scanned_at"] in report_html
    assert api_data["target_url"] in report_html
    assert "ID: f00ba4123456" in report_html


def test_render_report_html_malformed_evidence_handled_safely():
    """Verify malformed evidence types (dict, list, int, None, null bytes) do not crash report rendering."""
    payload = {
        "target": "https://malformed.example.com",
        "scanned_at": "2026-10-14T00:00:00Z",
        "modules": {
            "test_mod": {
                "status": "success",
                "findings": [
                    {"code": "F1", "severity": "info", "evidence": {"nested": "dict_evidence"}},
                    {"code": "F2", "severity": "low", "evidence": ["list", "of", "evidence"]},
                    {"code": "F3", "severity": "medium", "evidence": 12345},
                    {"code": "F4", "severity": "high", "evidence": None},
                    {"code": "F5", "severity": "critical", "evidence": "null\x00byte\x00string"},
                ],
            }
        },
    }

    html = render_report_html(
        payload,
        scan_id="malformed-ev-01",
        target_url="https://malformed.example.com",
    )

    assert "F1" in html
    assert "F2" in html
    assert "F3" in html
    assert "F4" in html
    assert "F5" in html


def test_render_report_html_empty_and_non_dict_modules_handled_safely():
    """Verify report rendering handles empty, None, and non-dict module entries gracefully."""
    payload = {
        "target": "https://empty-mods.example.com",
        "scanned_at": "2026-10-14T00:00:00Z",
        "modules": {
            "empty_mod": {},
            "none_mod": None,
            "str_mod": "unexpected string data",
            "list_mod": [1, 2, 3],
        },
    }

    html = render_report_html(
        payload,
        scan_id="empty-mods-01",
        target_url="https://empty-mods.example.com",
    )

    assert "Zentry Security Report" in html
    assert "No findings recorded." in html


def test_report_generation_exception_redacts_system_internals_and_paths(client, db_session):
    """Verify server-side report compilation exceptions never leak stack traces, paths, or internals to clients."""
    import uuid
    from app.core.security import create_access_token, get_password_hash
    from app.db.models import ScanJob, ScanStatusEnum, User
    from app.services.report_cache import clear_report_cache

    clear_report_cache()
    user = User(
        email=f"redact_{uuid.uuid4().hex[:8]}@example.com",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_access_token({"sub": str(user.id)})
    headers = {"Authorization": f"Bearer {token}"}

    job = ScanJob(
        user_id=user.id,
        target_url="https://redact.example.com",
        status=ScanStatusEnum.COMPLETED,
        result_payload={"target": "https://redact.example.com", "modules": {}},
    )
    db_session.add(job)
    db_session.commit()
    db_session.refresh(job)

    sensitive_exception_msg = (
        "/usr/local/lib/python3.11/site-packages/weasyprint/core.py: line 42: "
        "Segmentation fault at 0xdeadbeef: failed query to postgres://postgres:SecretPassword@10.0.0.5:5432/db"
    )

    with patch("app.api.v1.reports.generate_pdf", side_effect=RuntimeError(sensitive_exception_msg)):
        response = client.get(f"/api/v1/reports/{job.id}/pdf", headers=headers)

    assert response.status_code == 500
    resp_text = response.text

    # Assert no sensitive internal details leaked in response
    assert "/usr/local" not in resp_text
    assert "weasyprint/core.py" not in resp_text
    assert "Segmentation fault" not in resp_text
    assert "0xdeadbeef" not in resp_text
    assert "SecretPassword" not in resp_text
    assert "10.0.0.5" not in resp_text

    # Assert clean standardized error response structure
    data = response.json()
    assert "detail" in data
    if "error" in data:
        assert data["error"]["code"] in ("INTERNAL_SERVER_ERROR", "INTERNAL_ERROR")
        assert "request_id" in data["error"]


def test_report_generation_timeout_exception_handling(client, db_session):
    """Verify PDF compilation timeout exceptions return generic error responses without stack trace disclosure."""
    import uuid
    from app.core.security import create_access_token, get_password_hash
    from app.db.models import ScanJob, ScanStatusEnum, User
    from app.services.pdf_generator import PDFGenerationTimeoutError
    from app.services.report_cache import clear_report_cache

    clear_report_cache()
    user = User(
        email=f"timeout_{uuid.uuid4().hex[:8]}@example.com",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_access_token({"sub": str(user.id)})
    headers = {"Authorization": f"Bearer {token}"}

    job = ScanJob(
        user_id=user.id,
        target_url="https://timeout.example.com",
        status=ScanStatusEnum.COMPLETED,
        result_payload={"target": "https://timeout.example.com", "modules": {}},
    )
    db_session.add(job)
    db_session.commit()
    db_session.refresh(job)

    with patch("app.api.v1.reports.generate_pdf", side_effect=PDFGenerationTimeoutError("Deadline exceeded")):
        response = client.get(f"/api/v1/reports/{job.id}/pdf", headers=headers)

    assert response.status_code == 500
    assert "Traceback" not in response.text
    assert "generate_pdf" not in response.text
    data = response.json()
    assert "detail" in data



