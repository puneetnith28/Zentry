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


@pytest.mark.asyncio
async def test_inspect_headers_async_streams_without_buffering_body():
    from app.services.headers import inspect_headers_async

    chunks_consumed = []

    class MockAsyncStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            for i in range(100):
                chunks_consumed.append(i)
                yield b"X" * 1024 * 1024

    async def mock_handler(request: httpx.Request):
        return httpx.Response(
            200,
            headers={
                "server": "Apache/2.4.41",
                "x-frame-options": "DENY",
            },
            stream=MockAsyncStream(),
        )

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await inspect_headers_async("https://example.com", client=client)
        assert result["status"] == "success"
        assert result["status_code"] == 200
        assert result["headers"]["x-frame-options"] == "DENY"
        assert chunks_consumed == []


def test_hsts_disabled_when_max_age_zero():
    findings = _analyze_headers(
        {"strict-transport-security": "max-age=0"},
        [],
        is_https=True,
    )
    codes = [f.code for f in findings]
    assert "HSTS_DISABLED" in codes


def test_hsts_short_max_age_and_missing_subdomains():
    findings = _analyze_headers(
        {"strict-transport-security": "max-age=86400"},
        [],
        is_https=True,
    )
    codes = [f.code for f in findings]
    assert "HSTS_SHORT_MAX_AGE" in codes
    assert "HSTS_NO_SUBDOMAINS" in codes


def test_csp_unsafe_directives_and_wildcard():
    findings = _analyze_headers(
        {"content-security-policy": "default-src * 'unsafe-inline' 'unsafe-eval'"},
        [],
        is_https=True,
    )
    codes = [f.code for f in findings]
    assert "CSP_UNSAFE_DIRECTIVES" in codes
    assert "CSP_WILDCARD_SOURCE" in codes


def test_xcto_misconfigured_finding():
    findings = _analyze_headers(
        {"x-content-type-options": "none"},
        [],
        is_https=True,
    )
    codes = [f.code for f in findings]
    assert "MISCONFIGURED_X_CONTENT_TYPE_OPTIONS" in codes


def test_xfo_weak_and_misconfigured_findings():
    f_allow = _analyze_headers({"x-frame-options": "ALLOWALL"}, [], is_https=True)
    assert "WEAK_X_FRAME_OPTIONS" in [f.code for f in f_allow]

    f_invalid = _analyze_headers({"x-frame-options": "CUSTOM-ORIGIN"}, [], is_https=True)
    assert "MISCONFIGURED_X_FRAME_OPTIONS" in [f.code for f in f_invalid]


def test_cookie_security_multiple_cookies_and_prefixes():
    from app.services.headers import CookieInfo

    cookies = [
        # Normal cookie missing Secure and HttpOnly
        CookieInfo(name="session_id", secure=False, httponly=False, samesite="Lax"),
        # __Host- cookie missing Secure and setting Domain
        CookieInfo(name="__Host-token", secure=False, httponly=True, samesite="Strict", domain="example.com"),
        # __Secure- cookie missing Secure
        CookieInfo(name="__Secure-user", secure=False, httponly=True, samesite="Strict"),
        # Cookie with SameSite=None without Secure
        CookieInfo(name="cross_site", secure=False, httponly=True, samesite="None"),
        # Valid secure cookie
        CookieInfo(name="__Host-valid", secure=True, httponly=True, samesite="Strict"),
    ]

    findings = _analyze_headers({}, cookies, is_https=True)
    cookie_findings = [f for f in findings if f.code == "INSECURE_COOKIE"]

    # 4 cookies should be flagged as insecure, 1 (__Host-valid) should be clean
    assert len(cookie_findings) == 4

    messages = {f.message for f in cookie_findings}
    assert any("session_id" in m and "missing Secure" in m and "missing HttpOnly" in m for m in messages)
    assert any("__Host-token" in m and "__Host- requires Secure" in m and "__Host- must not set Domain" in m for m in messages)
    assert any("__Secure-user" in m and "__Secure- requires Secure" in m for m in messages)
    assert any("cross_site" in m and "SameSite=None requires Secure" in m for m in messages)


