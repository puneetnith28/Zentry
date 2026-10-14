import pytest
import httpx

pytestmark = pytest.mark.security


from app.core.outbound import (
    DEFAULT_MAX_RESPONSE_BYTES,
    ProhibitedDestinationError,
    SafeRedirectError,
    create_safe_async_client,
    is_prohibited_ip,
    resolve_public_target,
    safe_request,
    validate_ip_destination,
)
from app.services.headers import inspect_headers_async
from app.services.ports import scan_ports_async
from app.services.ssl import inspect_ssl_async
from app.services.subdomain import discover_subdomains_async
from app.services.technology import inspect_technology_async


PROHIBITED_IP_TEST_CASES = [
    "127.0.0.1",
    "127.0.0.2",
    "127.255.255.255",
    "10.0.0.1",
    "10.255.255.254",
    "172.16.0.1",
    "172.31.255.254",
    "192.168.0.1",
    "192.168.1.254",
    "169.254.169.254",  # AWS/GCP/Azure instance metadata
    "169.254.170.2",    # AWS ECS task metadata
    "100.64.0.1",       # Shared address space / CGNAT
    "0.0.0.0",
    "255.255.255.255",
    "::1",              # IPv6 loopback
    "::",               # IPv6 unspecified
    "fe80::1",          # IPv6 link-local
    "fc00::1",          # IPv6 unique local
    "fd12:3456::1",     # IPv6 unique local
    "::ffff:127.0.0.1", # IPv4-mapped IPv6 loopback
    "::ffff:10.0.0.1",  # IPv4-mapped IPv6 private
    "::ffff:169.254.169.254", # IPv4-mapped IPv6 metadata
]


@pytest.mark.parametrize("ip_str", PROHIBITED_IP_TEST_CASES)
def test_ssrf_prohibited_ip_matrix(ip_str):
    """Verify that all RFC prohibited ranges, metadata endpoints, and IPv6 representations are rejected."""
    with pytest.raises(ProhibitedDestinationError):
        validate_ip_destination(ip_str)


def test_ssrf_dns_rebinding_mixed_answers(monkeypatch):
    """Verify DNS multi-answer policy rejects targets resolving to any private IP."""
    mixed_answers = [
        (2, 1, 6, "", ("93.184.216.34", 443)),  # public
        (2, 1, 6, "", ("127.0.0.1", 443)),      # private
    ]
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: mixed_answers)

    with pytest.raises(ProhibitedDestinationError) as exc:
        resolve_public_target("rebind.attacker.com", 443)
    assert "resolves to prohibited address: 127.0.0.1" in str(exc.value)


@pytest.mark.asyncio
async def test_ssrf_redirect_hop_to_cloud_metadata(monkeypatch):
    """Verify safe_request intercepts redirect hops attempting to access cloud metadata."""
    async def mock_handler(request: httpx.Request):
        if "start" in str(request.url):
            return httpx.Response(
                302,
                headers={"location": "http://169.254.169.254/latest/meta-data/"},
            )
        return httpx.Response(200, text="metadata leaked")

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(ProhibitedDestinationError) as exc:
            await safe_request("GET", "http://example.com/start", client=client)
        assert "169.254.169.254" in str(exc.value)


@pytest.mark.asyncio
async def test_ssrf_redirect_hop_to_unsupported_schemes():
    """Verify safe_request rejects redirect hops to arbitrary protocols."""
    for scheme in ("file:///etc/passwd", "gopher://127.0.0.1:6379/_flushall", "dict://127.0.0.1:11211/"):
        async def mock_handler(request: httpx.Request, s=scheme):
            return httpx.Response(302, headers={"location": s})

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(SafeRedirectError):
                await safe_request("GET", "http://example.com/start", client=client)


@pytest.mark.asyncio
async def test_all_scanners_reject_loopback():
    """Verify all 5 scanner engines safely block attempts to scan 127.0.0.1."""
    target_url = "http://127.0.0.1:8000"
    target_host = "127.0.0.1"

    # 1. Headers Scanner
    headers_res = await inspect_headers_async(target_url)
    assert headers_res["status"] == "error"
    assert headers_res["error"]["code"] == "PROHIBITED_DESTINATION"

    # 2. Technology Scanner
    tech_res = await inspect_technology_async(target_url)
    assert tech_res["status"] == "error"
    assert tech_res["error"]["code"] == "PROHIBITED_DESTINATION"

    # 3. SSL Scanner
    ssl_res = await inspect_ssl_async(target_host)
    assert ssl_res["status"] == "error"
    assert ssl_res["error"]["code"] == "PROHIBITED_DESTINATION"

    # 4. Port Scanner
    ports_res = await scan_ports_async(target_host, ports=[80, 443])
    assert ports_res["status"] == "error"
    assert ports_res["error"]["code"] == "PROHIBITED_DESTINATION"

    # 5. Subdomain Scanner
    sub_res = await discover_subdomains_async(target_host)
    assert sub_res["status"] == "error"
    assert sub_res["error"]["code"] == "PROHIBITED_DESTINATION"


@pytest.mark.asyncio
async def test_all_scanners_reject_cloud_metadata():
    """Verify all 5 scanner engines safely block attempts to scan cloud metadata 169.254.169.254."""
    meta_url = "http://169.254.169.254/meta-data"
    meta_host = "169.254.169.254"

    headers_res = await inspect_headers_async(meta_url)
    assert headers_res["status"] == "error"
    assert headers_res["error"]["code"] == "PROHIBITED_DESTINATION"

    tech_res = await inspect_technology_async(meta_url)
    assert tech_res["status"] == "error"
    assert tech_res["error"]["code"] == "PROHIBITED_DESTINATION"

    ssl_res = await inspect_ssl_async(meta_host)
    assert ssl_res["status"] == "error"
    assert ssl_res["error"]["code"] == "PROHIBITED_DESTINATION"

    ports_res = await scan_ports_async(meta_host, ports=[80])
    assert ports_res["status"] == "error"
    assert ports_res["error"]["code"] == "PROHIBITED_DESTINATION"

    sub_res = await discover_subdomains_async(meta_host)
    assert sub_res["status"] == "error"
    assert sub_res["error"]["code"] == "PROHIBITED_DESTINATION"
