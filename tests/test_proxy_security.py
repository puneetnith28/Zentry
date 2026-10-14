import pytest
from starlette.requests import Request

from app.core.config import Settings
from app.core.proxy import get_client_ip, is_ip_in_trusted_list
from app.core.rate_limit import limiter, rate_limit_login


def make_mock_request(client_ip: str | None, headers: dict[str, str] | None = None) -> Request:
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/auth/login",
        "headers": [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in (headers or {}).items()],
    }
    if client_ip is not None:
        scope["client"] = (client_ip, 54321)
    else:
        scope["client"] = None
    return Request(scope)


@pytest.mark.security
def test_untrusted_peer_cannot_spoof_x_forwarded_for():
    # Peer is a public/untrusted IP attempting to spoof client IP via header
    request = make_mock_request(
        client_ip="203.0.113.99",
        headers={"x-forwarded-for": "1.1.1.1, 10.0.0.1"},
    )
    settings = Settings(trusted_proxies=["127.0.0.1", "10.0.0.0/8"])

    ip = get_client_ip(request, settings)
    assert ip == "203.0.113.99", "Untrusted peer's X-Forwarded-For must be ignored"


@pytest.mark.security
def test_trusted_peer_x_forwarded_for_is_honored():
    # Peer is localhost (trusted)
    request = make_mock_request(
        client_ip="127.0.0.1",
        headers={"x-forwarded-for": "198.51.100.42, 10.0.0.5"},
    )
    settings = Settings(trusted_proxies=["127.0.0.1"])

    ip = get_client_ip(request, settings)
    assert ip == "198.51.100.42", "Trusted peer's X-Forwarded-For should resolve to original client IP"


@pytest.mark.security
def test_trusted_cidr_subnet_peer():
    # Peer is within trusted 172.16.0.0/12 subnet
    request = make_mock_request(
        client_ip="172.16.4.10",
        headers={"x-real-ip": "198.51.100.77"},
    )
    settings = Settings(trusted_proxies=["172.16.0.0/12"])

    ip = get_client_ip(request, settings)
    assert ip == "198.51.100.77"


@pytest.mark.security
def test_malformed_forwarded_headers_fall_back_safely():
    request = make_mock_request(
        client_ip="127.0.0.1",
        headers={"x-forwarded-for": "not-an-ip, <script>alert(1)</script>"},
    )
    settings = Settings(trusted_proxies=["127.0.0.1"])

    ip = get_client_ip(request, settings)
    assert ip == "127.0.0.1"


@pytest.mark.security
def test_rate_limiter_uses_trusted_client_ip(monkeypatch):
    limiter.clear()
    settings = Settings(trusted_proxies=["127.0.0.1"], auth_rate_limit_per_minute=2)
    monkeypatch.setattr("app.core.rate_limit.get_settings", lambda: settings)

    # Untrusted attacker tries to bypass rate limit by sending changing X-Forwarded-For
    for i in range(2):
        req = make_mock_request(
            client_ip="203.0.113.5",
            headers={"x-forwarded-for": f"10.0.0.{i+1}"},
        )
        rate_limit_login(req)

    # Third attempt from same untrusted peer must be blocked regardless of spoofed header
    req3 = make_mock_request(
        client_ip="203.0.113.5",
        headers={"x-forwarded-for": "10.0.0.99"},
    )
    with pytest.raises(Exception) as excinfo:
        rate_limit_login(req3)
    assert "Rate limit exceeded" in str(excinfo.value)

