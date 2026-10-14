import asyncio
import errno
import socket
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.ports import (
    DEFAULT_PORTS,
    MAX_PORT_COUNT,
    _probe_port,
    _resolve_host,
    scan_ports_async,
)


def test_resolve_host():
    assert _resolve_host("https://example.com/test") == "example.com"
    assert _resolve_host("example.com:8080") == "example.com"
    assert _resolve_host("192.168.1.1") == "192.168.1.1"


def test_resolve_host_invalid():
    with pytest.raises(ValueError, match="Invalid target"):
        _resolve_host("   ")


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
async def test_scan_ports_invalid_target():
    result = await scan_ports_async("")
    assert result["status"] == "error"
    assert result["error"]["code"] == "INVALID_TARGET"


@pytest.mark.asyncio
async def test_scan_ports_dns_failure(monkeypatch):
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *args, **kwargs: (_ for _ in ()).throw(socket.gaierror("Name or service not known")),
    )
    result = await scan_ports_async("nonexistent.invalid", ports=[80])
    assert result["status"] == "error"
    assert result["error"]["code"] == "DNS_FAILED"


@pytest.mark.asyncio
async def test_scan_ports_invalid_ports_list():
    result = await scan_ports_async("example.com", ports=[70000, -5, "http"])  # type: ignore
    assert result["status"] == "error"
    assert result["error"]["code"] == "INVALID_PORTS"


@pytest.mark.asyncio
async def test_probe_port_states(monkeypatch):
    # 1. Successful connection -> "open"
    mock_writer = MagicMock()
    mock_writer.close = MagicMock()
    mock_writer.wait_closed = AsyncMock()

    async def mock_open_conn_success(host, port):
        return MagicMock(), mock_writer

    monkeypatch.setattr(asyncio, "open_connection", mock_open_conn_success)
    assert await _probe_port("1.2.3.4", 80, timeout=1.0) == "open"

    # 1b. Successful connection even if writer.close raises -> "open"
    mock_writer_err = MagicMock()
    mock_writer_err.close = MagicMock(side_effect=ConnectionResetError("Reset"))
    mock_writer_err.wait_closed = AsyncMock()

    async def mock_open_conn_writer_err(host, port):
        return MagicMock(), mock_writer_err

    monkeypatch.setattr(asyncio, "open_connection", mock_open_conn_writer_err)
    assert await _probe_port("1.2.3.4", 80, timeout=1.0) == "open"

    # 2. ConnectionRefusedError -> "closed"
    async def mock_open_conn_refused(host, port):
        raise ConnectionRefusedError("Connection refused")

    monkeypatch.setattr(asyncio, "open_connection", mock_open_conn_refused)
    assert await _probe_port("1.2.3.4", 80, timeout=1.0) == "closed"

    # 3. ConnectionResetError -> "closed"
    async def mock_open_conn_reset(host, port):
        raise ConnectionResetError("Connection reset by peer")

    monkeypatch.setattr(asyncio, "open_connection", mock_open_conn_reset)
    assert await _probe_port("1.2.3.4", 80, timeout=1.0) == "closed"

    # 4. OSError(ECONNREFUSED) -> "closed"
    async def mock_open_conn_os_refused(host, port):
        raise OSError(errno.ECONNREFUSED, "Connection refused")

    monkeypatch.setattr(asyncio, "open_connection", mock_open_conn_os_refused)
    assert await _probe_port("1.2.3.4", 80, timeout=1.0) == "closed"

    # 5. asyncio.TimeoutError -> "filtered"
    async def mock_open_conn_async_timeout(host, port):
        raise asyncio.TimeoutError()

    monkeypatch.setattr(asyncio, "open_connection", mock_open_conn_async_timeout)
    assert await _probe_port("1.2.3.4", 80, timeout=1.0) == "filtered"

    # 6. socket.timeout -> "filtered"
    async def mock_open_conn_socket_timeout(host, port):
        raise socket.timeout()

    monkeypatch.setattr(asyncio, "open_connection", mock_open_conn_socket_timeout)
    assert await _probe_port("1.2.3.4", 80, timeout=1.0) == "filtered"

    # 7. OSError(ETIMEDOUT) -> "filtered"
    async def mock_open_conn_etimedout(host, port):
        raise OSError(errno.ETIMEDOUT, "Connection timed out")

    monkeypatch.setattr(asyncio, "open_connection", mock_open_conn_etimedout)
    assert await _probe_port("1.2.3.4", 80, timeout=1.0) == "filtered"

    # 8. OSError(EHOSTUNREACH) -> "filtered"
    async def mock_open_conn_hostunreach(host, port):
        raise OSError(errno.EHOSTUNREACH, "No route to host")

    monkeypatch.setattr(asyncio, "open_connection", mock_open_conn_hostunreach)
    assert await _probe_port("1.2.3.4", 80, timeout=1.0) == "filtered"

    # 9. OSError(ENETUNREACH) -> "filtered"
    async def mock_open_conn_netunreach(host, port):
        raise OSError(errno.ENETUNREACH, "Network is unreachable")

    monkeypatch.setattr(asyncio, "open_connection", mock_open_conn_netunreach)
    assert await _probe_port("1.2.3.4", 80, timeout=1.0) == "filtered"

    # 10. PermissionError(EACCES) / EPERM -> "filtered"
    async def mock_open_conn_perm(host, port):
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(asyncio, "open_connection", mock_open_conn_perm)
    assert await _probe_port("1.2.3.4", 80, timeout=1.0) == "filtered"


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
    assert result["filtered_ports"] == []


@pytest.mark.asyncio
async def test_scan_ports_open_closed_filtered_and_findings(monkeypatch):
    fake_addrinfo = [(2, 1, 6, "", ("93.184.216.34", 80))]
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: fake_addrinfo)

    port_states = {
        21: "open",        # FTP_OPEN
        80: "open",        # NO_HTTPS_PORT (since 443 is closed)
        443: "closed",
        8080: "filtered",
        8443: "filtered",
        3306: "closed",
    }

    async def mock_probe_port(host, port, timeout):
        return port_states.get(port, "closed")

    monkeypatch.setattr("app.services.ports._probe_port", mock_probe_port)

    result = await scan_ports_async("example.com", ports=[21, 80, 443, 8080, 8443, 3306])
    assert result["status"] == "success"
    assert result["open_ports"] == [21, 80]
    assert result["closed_ports"] == [443, 3306]
    assert result["filtered_ports"] == [8080, 8443]

    finding_codes = {f["code"] for f in result["findings"]}
    assert "FTP_OPEN" in finding_codes
    assert "NO_HTTPS_PORT" in finding_codes


@pytest.mark.asyncio
async def test_scan_ports_port_list_deduplication_and_capping(monkeypatch):
    fake_addrinfo = [(2, 1, 6, "", ("93.184.216.34", 80))]
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: fake_addrinfo)

    probed_ports: list[int] = []

    async def mock_probe_port(host, port, timeout):
        probed_ports.append(port)
        return "closed"

    monkeypatch.setattr("app.services.ports._probe_port", mock_probe_port)

    # 60 ports with duplicates and invalid entries
    test_ports = [80, 80, 80, -1, 70000] + list(range(1000, 1070))
    result = await scan_ports_async("example.com", ports=test_ports)
    assert result["status"] == "success"
    assert len(probed_ports) <= MAX_PORT_COUNT
    assert len(set(probed_ports)) == len(probed_ports)  # No duplicate probes
    assert 80 in probed_ports
    assert -1 not in probed_ports
    assert 70000 not in probed_ports

