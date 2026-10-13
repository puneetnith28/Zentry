import pytest

from app.services.ports import _resolve_host, scan_ports_async


def test_resolve_host():
    assert _resolve_host("https://example.com/test") == "example.com"
    assert _resolve_host("example.com:8080") == "example.com"
    assert _resolve_host("192.168.1.1") == "192.168.1.1"


@pytest.mark.asyncio
async def test_scan_ports_blocks_prohibited_destination():
    result = await scan_ports_async("127.0.0.1", ports=[80, 443])
    assert result["status"] == "error"
    assert result["error"]["code"] == "PROHIBITED_DESTINATION"
    assert "prohibited address: 127.0.0.1" in result["error"]["message"]


@pytest.mark.asyncio
async def test_scan_ports_blocks_cloud_metadata():
    result = await scan_ports_async("169.254.169.254", ports=[80])
    assert result["status"] == "error"
    assert result["error"]["code"] == "PROHIBITED_DESTINATION"
    assert "prohibited address: 169.254.169.254" in result["error"]["message"]


@pytest.mark.asyncio
async def test_scan_ports_successful_mock(monkeypatch):
    fake_addrinfo = [(2, 1, 6, "", ("93.184.216.34", 80))]
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: fake_addrinfo)

    async def mock_probe_port(host, port, timeout):
        if port == 80:
            return "open"
        return "closed"

    monkeypatch.setattr("app.services.ports._probe_port", mock_probe_port)

    result = await scan_ports_async("example.com", ports=[80, 8080])
    assert result["status"] == "success"
    assert result["host"] == "example.com"
    assert 80 in result["open_ports"]
    assert 8080 in result["closed_ports"]
