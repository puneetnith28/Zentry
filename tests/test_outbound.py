import pytest
from app.core.outbound import (
    DNSResolutionError,
    ProhibitedDestinationError,
    is_prohibited_ip,
    resolve_public_target,
    validate_ip_destination,
)


@pytest.mark.parametrize(
    "public_ip",
    [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "142.250.190.46",
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
        "::ffff:8.8.8.8",  # Public IPv4 mapped to IPv6
    ],
)
def test_public_ips_permitted(public_ip: str):
    assert not is_prohibited_ip(public_ip)
    validated = validate_ip_destination(public_ip)
    assert validated is not None


@pytest.mark.parametrize(
    "prohibited_ip",
    [
        # Loopback
        "127.0.0.1",
        "127.0.0.254",
        "127.1.2.3",
        "::1",
        "::ffff:127.0.0.1",
        # Private RFC 1918
        "10.0.0.1",
        "10.255.255.254",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.0.1",
        "192.168.100.200",
        "::ffff:10.0.0.1",
        "::ffff:192.168.1.1",
        # Link-local / Cloud Metadata
        "169.254.169.254",
        "169.254.1.1",
        "fe80::1",
        "fe80::dead:beef",
        "::ffff:169.254.169.254",
        # CGNAT RFC 6598
        "100.64.0.1",
        "100.127.255.254",
        # Documentation & Testnet
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "2001:db8::1",
        # Multicast & Broadcast
        "224.0.0.1",
        "239.255.255.250",
        "ff02::1",
        "255.255.255.255",
        # Current / Unspecified
        "0.0.0.0",
        "::",
        # IPv6 ULA
        "fc00::1",
        "fd00:1234::1",
    ],
)
def test_prohibited_ips_blocked(prohibited_ip: str):
    assert is_prohibited_ip(prohibited_ip)
    with pytest.raises(ProhibitedDestinationError):
        validate_ip_destination(prohibited_ip)


def test_invalid_ip_representation_rejected():
    assert is_prohibited_ip("not-an-ip")
    with pytest.raises(ProhibitedDestinationError):
        validate_ip_destination("not-an-ip")


def test_resolve_public_target_ip_literal():
    ips = resolve_public_target("93.184.216.34")
    assert len(ips) == 1
    assert str(ips[0]) == "93.184.216.34"

    with pytest.raises(ProhibitedDestinationError):
        resolve_public_target("127.0.0.1")


def test_resolve_public_target_success(monkeypatch):
    fake_addrinfo = [
        (2, 1, 6, "", ("93.184.216.34", 443)),
        (10, 1, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 443)),
    ]
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: fake_addrinfo)

    ips = resolve_public_target("example.com", 443)
    assert len(ips) == 2
    assert str(ips[0]) == "93.184.216.34"
    assert str(ips[1]) == "2606:2800:220:1:248:1893:25c8:1946"


def test_resolve_public_target_private_blocked(monkeypatch):
    fake_addrinfo = [
        (2, 1, 6, "", ("10.0.0.1", 443)),
    ]
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: fake_addrinfo)

    with pytest.raises(ProhibitedDestinationError) as exc:
        resolve_public_target("internal.corp", 443)
    assert "resolves to prohibited address" in str(exc.value)


def test_resolve_public_target_mixed_answers_blocked(monkeypatch):
    """If DNS returns both public and private addresses, the target MUST be rejected."""
    fake_addrinfo = [
        (2, 1, 6, "", ("93.184.216.34", 443)),
        (2, 1, 6, "", ("192.168.1.1", 443)),
    ]
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: fake_addrinfo)

    with pytest.raises(ProhibitedDestinationError) as exc:
        resolve_public_target("rebinding-test.com", 443)
    assert "resolves to prohibited address: 192.168.1.1" in str(exc.value)


def test_resolve_public_target_gaierror(monkeypatch):
    def fake_gaierror(*args, **kwargs):
        import socket
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr("socket.getaddrinfo", fake_gaierror)

    from app.core.outbound import DNSResolutionError
    with pytest.raises(DNSResolutionError) as exc:
        resolve_public_target("nonexistent.invalid", 80)
    assert "Unable to resolve hostname" in str(exc.value)


def test_resolve_public_target_empty_hostname():
    from app.core.outbound import DNSResolutionError
    with pytest.raises(DNSResolutionError):
        resolve_public_target("   ")


@pytest.mark.asyncio
async def test_safe_transport_blocks_loopback_connection():
    from app.core.outbound import create_safe_async_client, ProhibitedDestinationError
    async with create_safe_async_client() as client:
        with pytest.raises(ProhibitedDestinationError) as exc:
            await client.get("http://127.0.0.1:8000/test")
        assert "prohibited address: 127.0.0.1" in str(exc.value)


@pytest.mark.asyncio
async def test_safe_transport_blocks_private_dns_resolution(monkeypatch):
    from app.core.outbound import create_safe_async_client, ProhibitedDestinationError
    fake_addrinfo = [(2, 1, 6, "", ("169.254.169.254", 80))]
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: fake_addrinfo)

    async with create_safe_async_client() as client:
        with pytest.raises(ProhibitedDestinationError) as exc:
            await client.get("http://metadata.cloud.internal/latest")
        assert "resolves to prohibited address: 169.254.169.254" in str(exc.value)


@pytest.mark.asyncio
async def test_safe_client_defaults():
    from app.core.outbound import create_safe_async_client, SafeAsyncHTTPTransport
    client = create_safe_async_client(timeout=15.0)
    assert not client.follow_redirects
    assert not client.trust_env
    assert client.timeout.connect == 15.0
    assert isinstance(client._transport, SafeAsyncHTTPTransport)
    await client.aclose()


@pytest.mark.asyncio
async def test_safe_request_redirect_to_private_blocked(monkeypatch):
    import httpx
    from app.core.outbound import safe_request, ProhibitedDestinationError

    async def mock_handler(request: httpx.Request):
        if "start" in str(request.url):
            return httpx.Response(302, headers={"location": "http://127.0.0.1:8000/internal"})
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(ProhibitedDestinationError) as exc:
            await safe_request("GET", "http://example.com/start", client=client)
        assert "resolves to prohibited address: 127.0.0.1" in str(exc.value)


@pytest.mark.asyncio
async def test_safe_request_redirect_to_prohibited_scheme():
    import httpx
    from app.core.outbound import safe_request, SafeRedirectError

    async def mock_handler(request: httpx.Request):
        return httpx.Response(302, headers={"location": "file:///etc/passwd"})

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(SafeRedirectError) as exc:
            await safe_request("GET", "http://example.com/start", client=client)
        assert "prohibited scheme 'file'" in str(exc.value)


@pytest.mark.asyncio
async def test_safe_request_max_redirects_exceeded(monkeypatch):
    import httpx
    from app.core.outbound import safe_request, MaxRedirectsExceededError

    fake_addrinfo = [(2, 1, 6, "", ("93.184.216.34", 80))]
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: fake_addrinfo)

    async def mock_handler(request: httpx.Request):
        return httpx.Response(302, headers={"location": "http://example.com/loop"})

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(MaxRedirectsExceededError) as exc:
            await safe_request("GET", "http://example.com/loop", client=client, max_redirects=3)
        assert "Maximum redirect hops (3) exceeded" in str(exc.value)


@pytest.mark.asyncio
async def test_safe_request_successful_public_redirect(monkeypatch):
    import httpx
    from app.core.outbound import safe_request

    fake_addrinfo = [(2, 1, 6, "", ("93.184.216.34", 443))]
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: fake_addrinfo)

    async def mock_handler(request: httpx.Request):
        if str(request.url) == "http://example.com/":
            return httpx.Response(301, headers={"location": "https://example.com/final"})
        return httpx.Response(200, text="Destination reached successfully")

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        res = await safe_request("GET", "http://example.com/", client=client)
        assert res.status_code == 200
        assert res.text == "Destination reached successfully"


def test_validate_proxy_url_rejects_unsupported_scheme():
    from app.core.outbound import validate_proxy_url, ProhibitedProxyError

    with pytest.raises(ProhibitedProxyError) as exc:
        validate_proxy_url("socks5://proxy.example.com:1080")
    assert "Unsupported proxy scheme 'socks5'" in str(exc.value)


def test_validate_proxy_url_rejects_private_and_metadata_ip():
    from app.core.outbound import validate_proxy_url, ProhibitedDestinationError

    for bad_proxy in (
        "http://127.0.0.1:8080",
        "http://10.0.0.5:3128",
        "http://169.254.169.254:8080",
        "http://[::1]:8080",
    ):
        with pytest.raises(ProhibitedDestinationError):
            validate_proxy_url(bad_proxy)


def test_validate_proxy_url_allows_public_target(monkeypatch):
    from app.core.outbound import validate_proxy_url

    fake_addrinfo = [(2, 1, 6, "", ("93.184.216.34", 8080))]
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: fake_addrinfo)
    # Should not raise
    validate_proxy_url("http://corporate-proxy.example.com:8080")


@pytest.mark.asyncio
async def test_create_safe_client_suppresses_environment_proxy(monkeypatch):
    import os
    from app.core.outbound import create_safe_async_client

    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:8888")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8888")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:8888")

    client = create_safe_async_client()
    try:
        assert client._transport._pool is not None
        # Verify ambient environment proxies did not create proxy mounts
        assert len(client._mounts) == 0
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_create_safe_client_rejects_private_proxy():
    from app.core.outbound import create_safe_async_client, ProhibitedDestinationError

    with pytest.raises(ProhibitedDestinationError):
        create_safe_async_client(proxy="http://10.0.0.1:8080")


def test_default_timeout_configuration():
    from app.core.outbound import (
        get_default_timeout,
        DEFAULT_CONNECT_TIMEOUT,
        DEFAULT_READ_TIMEOUT,
        DEFAULT_WRITE_TIMEOUT,
        DEFAULT_POOL_TIMEOUT,
    )
    timeout = get_default_timeout()
    assert timeout.connect == DEFAULT_CONNECT_TIMEOUT
    assert timeout.read == DEFAULT_READ_TIMEOUT
    assert timeout.write == DEFAULT_WRITE_TIMEOUT
    assert timeout.pool == DEFAULT_POOL_TIMEOUT


@pytest.mark.asyncio
async def test_safe_request_enforces_content_length_limit():
    import httpx
    from app.core.outbound import safe_request, ResponseBodyTooLargeError

    async def mock_handler(request: httpx.Request):
        return httpx.Response(
            200,
            headers={"content-length": "2000000"},
            text="large response placeholder",
        )

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(ResponseBodyTooLargeError) as exc:
            await safe_request(
                "GET",
                "http://example.com/huge",
                client=client,
                max_response_bytes=1000,
            )
        assert "Content-Length" in str(exc.value)


@pytest.mark.asyncio
async def test_safe_request_enforces_body_size_limit():
    import httpx
    from app.core.outbound import safe_request, ResponseBodyTooLargeError

    async def mock_handler(request: httpx.Request):
        res = httpx.Response(200, text="A" * 5000)
        del res.headers["content-length"]
        return res

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(ResponseBodyTooLargeError) as exc:
            await safe_request(
                "GET",
                "http://example.com/body",
                client=client,
                max_response_bytes=1000,
            )
        assert "Response body" in str(exc.value)



@pytest.mark.asyncio
async def test_safe_request_within_body_size_limit():
    import httpx
    from app.core.outbound import safe_request

    async def mock_handler(request: httpx.Request):
        return httpx.Response(200, text="small body")

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        res = await safe_request(
            "GET",
            "http://example.com/ok",
            client=client,
            max_response_bytes=1000,
        )
        assert res.status_code == 200
        assert res.text == "small body"


@pytest.mark.asyncio
async def test_read_bounded_response_stream():
    import httpx
    from app.core.outbound import read_bounded_response_stream, ResponseBodyTooLargeError

    # Test small stream
    res_ok = httpx.Response(200, content=b"1234567890")
    data = await read_bounded_response_stream(res_ok, max_bytes=20)
    assert data == b"1234567890"

    # Test stream exceeding limit
    res_large = httpx.Response(200, content=b"A" * 100)
    with pytest.raises(ResponseBodyTooLargeError):
        await read_bounded_response_stream(res_large, max_bytes=50, chunk_size=10)
