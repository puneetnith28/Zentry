import pytest

from app.services.ssl import _parse_target


@pytest.mark.parametrize(
    ("target", "port", "expected_host", "expected_port"),
    [
        ("example.com", None, "example.com", 443),
        ("example.com:8443", None, "example.com", 8443),
        ("https://example.com/path", None, "example.com", 443),
        ("https://example.com:8443", None, "example.com", 8443),
    ],
)
def test_parse_target(target, port, expected_host, expected_port):
    host, resolved = _parse_target(target, port)
    assert host == expected_host
    assert resolved == expected_port


@pytest.mark.asyncio
async def test_inspect_ssl_blocks_prohibited_destination():
    from app.services.ssl import inspect_ssl_async

    result = await inspect_ssl_async("127.0.0.1")
    assert result["status"] == "error"
    assert result["error"]["code"] == "PROHIBITED_DESTINATION"
