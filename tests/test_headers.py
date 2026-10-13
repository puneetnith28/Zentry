from app.services.headers import _analyze_headers


def test_missing_hsts_on_https():
    findings = _analyze_headers({}, [], is_https=True)
    codes = [f.code for f in findings]
    assert "MISSING_HSTS" in codes


def test_insecure_cookie_finding():
    from app.services.headers import CookieInfo

    cookies = [CookieInfo(name="session", secure=False, httponly=False, samesite=None)]
    findings = _analyze_headers({"content-security-policy": "default-src 'self'"}, cookies, is_https=True)
    codes = [f.code for f in findings]
    assert "INSECURE_COOKIE" in codes


import pytest
import httpx


@pytest.mark.asyncio
async def test_inspect_headers_async_blocks_prohibited_destination():
    from app.services.headers import inspect_headers_async

    result = await inspect_headers_async("http://127.0.0.1:8000")
    assert result["status"] == "error"
    assert result["error"]["code"] == "PROHIBITED_DESTINATION"
    assert "prohibited address: 127.0.0.1" in result["error"]["message"]


@pytest.mark.asyncio
async def test_inspect_headers_async_blocks_cloud_metadata():
    from app.services.headers import inspect_headers_async

    result = await inspect_headers_async("http://169.254.169.254/latest/meta-data")
    assert result["status"] == "error"
    assert result["error"]["code"] == "PROHIBITED_DESTINATION"
    assert "prohibited address: 169.254.169.254" in result["error"]["message"]


@pytest.mark.asyncio
async def test_inspect_headers_async_success_with_mock_client():
    from app.services.headers import inspect_headers_async

    async def mock_handler(request: httpx.Request):
        return httpx.Response(
            200,
            headers={
                "strict-transport-security": "max-age=31536000; includeSubDomains",
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "referrer-policy": "no-referrer",
                "permissions-policy": "camera=()",
            },
        )

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await inspect_headers_async("https://example.com", client=client)
        assert result["status"] == "success"
        assert result["status_code"] == 200
        assert result["headers"]["x-frame-options"] == "DENY"
        # Since all recommended headers are present, there should be no missing header findings
        codes = [f["code"] for f in result["findings"]]
        assert "MISSING_HSTS" not in codes
        assert "MISSING_CSP" not in codes


@pytest.mark.asyncio
async def test_inspect_headers_async_enforces_byte_limits():
    from app.services.headers import inspect_headers_async

    async def mock_handler(request: httpx.Request):
        return httpx.Response(
            200,
            headers={"content-length": "500000"},  # exceeds 64 KB
            text="overflow body",
        )

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await inspect_headers_async("https://example.com", client=client)
        assert result["status"] == "error"
        assert result["error"]["code"] == "RESPONSE_TOO_LARGE"
