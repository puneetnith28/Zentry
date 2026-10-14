"""
Centralized Outbound Network Policy and Security Controls.

Enforces connection-level destination validation, SSRF defenses,
IP classification, safe DNS resolution, and pinned connections.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
import ipaddress
import socket
from typing import AsyncIterator, Final
from urllib.parse import urljoin, urlparse

import httpcore
import httpx


class ProhibitedDestinationError(ValueError):
    """Raised when an outbound network destination violates security policy."""
    pass


class DNSResolutionError(ValueError):
    """Raised when DNS resolution for an outbound target fails."""
    pass


class SafeRedirectError(ProhibitedDestinationError):
    """Raised when an HTTP redirect targets a prohibited destination or protocol."""
    pass


class MaxRedirectsExceededError(ValueError):
    """Raised when an HTTP request exceeds maximum allowed redirect hops."""
    pass


class ProhibitedProxyError(ProhibitedDestinationError):
    """Raised when an explicit outbound proxy configuration targets a prohibited destination or protocol."""
    pass


class ResponseBodyTooLargeError(ValueError):
    """Raised when an HTTP response body exceeds configured byte budget."""
    pass


# Centralized timeout constants (in seconds)
DEFAULT_CONNECT_TIMEOUT: Final[float] = 5.0
DEFAULT_READ_TIMEOUT: Final[float] = 10.0
DEFAULT_WRITE_TIMEOUT: Final[float] = 5.0
DEFAULT_POOL_TIMEOUT: Final[float] = 5.0
DEFAULT_REQUEST_TIMEOUT: Final[float] = 10.0

# Centralized response body size caps (in bytes)
DEFAULT_MAX_RESPONSE_BYTES: Final[int] = 1024 * 1024        # 1 MB
DEFAULT_TECH_MAX_RESPONSE_BYTES: Final[int] = 256 * 1024    # 256 KB
DEFAULT_HEADERS_MAX_RESPONSE_BYTES: Final[int] = 64 * 1024  # 64 KB


# Comprehensive IPv4 prohibited ranges (RFC 1918, 1122, 3927, 5771, 6598, etc.)
PROHIBITED_IPV4_NETWORKS: Final[tuple[ipaddress.IPv4Network, ...]] = (
    ipaddress.ip_network("0.0.0.0/8"),          # Current network / "this host"
    ipaddress.ip_network("10.0.0.0/8"),         # Private RFC 1918
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space / CGNAT RFC 6598
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback RFC 1122
    ipaddress.ip_network("169.254.0.0/16"),     # Link Local RFC 3927 (includes 169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # Private RFC 1918
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments RFC 6890
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1 Documentation RFC 5737
    ipaddress.ip_network("192.88.99.0/24"),     # 6to4 Relay Anycast RFC 7526
    ipaddress.ip_network("192.168.0.0/16"),     # Private RFC 1918
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmark testing RFC 2544
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2 Documentation RFC 5737
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3 Documentation RFC 5737
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast RFC 5771
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved RFC 1112
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast RFC 919
)

# Comprehensive IPv6 prohibited ranges (RFC 4291, 4193, 3849, 6666, etc.)
PROHIBITED_IPV6_NETWORKS: Final[tuple[ipaddress.IPv6Network, ...]] = (
    ipaddress.ip_network("::/128"),             # Unspecified address RFC 4291
    ipaddress.ip_network("::1/128"),            # Loopback RFC 4291
    ipaddress.ip_network("100::/64"),           # Discard-only prefix RFC 6666
    ipaddress.ip_network("2001::/23"),          # IETF protocol assignments
    ipaddress.ip_network("2001:db8::/32"),      # Documentation RFC 3849
    ipaddress.ip_network("2002::/16"),          # 6to4 relay RFC 3056
    ipaddress.ip_network("fc00::/7"),           # Unique Local RFC 4193
    ipaddress.ip_network("fe80::/10"),          # Link-local unicast RFC 4291
    ipaddress.ip_network("ff00::/8"),           # Multicast RFC 4291
)


def parse_ip_address(
    ip_or_str: ipaddress.IPv4Address | ipaddress.IPv6Address | str
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse string or IP object into an IPv4Address or IPv6Address."""
    if isinstance(ip_or_str, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return ip_or_str
    try:
        return ipaddress.ip_address(str(ip_or_str).strip())
    except ValueError as exc:
        raise ProhibitedDestinationError(f"Invalid IP address representation: {ip_or_str}") from exc


def is_prohibited_ip(
    ip_or_str: ipaddress.IPv4Address | ipaddress.IPv6Address | str
) -> bool:
    """
    Deterministically evaluates whether an IP destination is prohibited.
    
    Blocks:
    - Loopback, private, link-local, unspecified, multicast, reserved addresses.
    - Cloud metadata (e.g., 169.254.169.254).
    - IPv4-mapped IPv6 addresses representing prohibited IPv4 destinations.
    """
    try:
        ip = parse_ip_address(ip_or_str)
    except ProhibitedDestinationError:
        return True

    # Check IPv4-mapped IPv6 address (::ffff:w.x.y.z)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return is_prohibited_ip(ip.ipv4_mapped)

    # Standard built-in classification flags
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True

    # Explicit prohibited network range checking
    if isinstance(ip, ipaddress.IPv4Address):
        return any(ip in net for net in PROHIBITED_IPV4_NETWORKS)
    elif isinstance(ip, ipaddress.IPv6Address):
        return any(ip in net for net in PROHIBITED_IPV6_NETWORKS)

    return True


def validate_ip_destination(
    ip_or_str: ipaddress.IPv4Address | ipaddress.IPv6Address | str
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """
    Validate that an IP address is permissible as an outbound scan destination.
    
    Returns the parsed IP address or raises ProhibitedDestinationError.
    """
    ip = parse_ip_address(ip_or_str)
    if is_prohibited_ip(ip):
        raise ProhibitedDestinationError(
            f"Outbound connection to prohibited destination blocked: {ip}"
        )
    return ip


def resolve_public_target(
    hostname: str,
    port: int = 0,
    *,
    family: int = socket.AF_UNSPEC,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    """
    Resolve a hostname and verify that every returned IP address is strictly public.
    
    Enforces safe multi-answer policy: if ANY returned IP address is prohibited,
    the entire target is rejected to protect against DNS rebinding and split-horizon SSRF.
    
    Returns a tuple of validated IP address objects.
    """
    clean_host = hostname.strip().rstrip(".")
    if not clean_host:
        raise DNSResolutionError("Empty hostname provided for DNS resolution")

    # If the target is already an IP address, validate it directly
    try:
        ip = ipaddress.ip_address(clean_host)
        return (validate_ip_destination(ip),)
    except ValueError:
        pass  # Hostname string, proceed with DNS lookup

    try:
        addrinfo = socket.getaddrinfo(
            clean_host,
            port,
            family=family,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise DNSResolutionError(f"Unable to resolve hostname: {clean_host}") from exc

    if not addrinfo:
        raise DNSResolutionError(f"No DNS records returned for hostname: {clean_host}")

    resolved_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    seen: set[str] = set()

    for item in addrinfo:
        sockaddr = item[4]
        ip_str = sockaddr[0]
        if ip_str in seen:
            continue
        seen.add(ip_str)

        try:
            ip = parse_ip_address(ip_str)
        except ProhibitedDestinationError as exc:
            raise ProhibitedDestinationError(
                f"Target {clean_host} resolved to invalid IP address: {ip_str}"
            ) from exc

        if is_prohibited_ip(ip):
            raise ProhibitedDestinationError(
                f"Target {clean_host} resolves to prohibited address: {ip_str}"
            )

        resolved_ips.append(ip)

    if not resolved_ips:
        raise DNSResolutionError(f"No valid IP addresses resolved for hostname: {clean_host}")

    return tuple(resolved_ips)


class PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Network backend that intercepts TCP connections and pins them to pre-validated public IPs."""

    def __init__(self, inner: httpcore.AsyncNetworkBackend) -> None:
        self._inner = inner

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options = None,
    ) -> httpcore.AsyncNetworkStream:
        resolved = resolve_public_target(host, port)
        pinned_ip = str(resolved[0])
        return await self._inner.connect_tcp(
            pinned_ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(self, *args, **kwargs) -> httpcore.AsyncNetworkStream:
        return await self._inner.connect_unix_socket(*args, **kwargs)

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class SafeAsyncHTTPTransport(httpx.AsyncHTTPTransport):
    """Custom HTTP transport that pins connections to pre-validated public IPs to prevent DNS rebinding."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        orig_backend = getattr(self._pool, "_network_backend", None)
        if orig_backend is not None:
            self._pool._network_backend = PinnedNetworkBackend(orig_backend)


def validate_proxy_url(proxy_url: str) -> None:
    """Validate that an explicit proxy URL uses safe protocols and resolves to allowed public IP destinations."""
    parsed = urlparse(proxy_url)
    if parsed.scheme not in ("http", "https"):
        raise ProhibitedProxyError(
            f"Unsupported proxy scheme '{parsed.scheme}'; only http and https are allowed."
        )
    if not parsed.hostname:
        raise ProhibitedProxyError(f"Missing proxy hostname in URL: {proxy_url}")
    default_port = 443 if parsed.scheme == "https" else 80
    port = parsed.port or default_port
    resolve_public_target(parsed.hostname, port)


def get_default_timeout(
    connect: float = DEFAULT_CONNECT_TIMEOUT,
    read: float = DEFAULT_READ_TIMEOUT,
    write: float = DEFAULT_WRITE_TIMEOUT,
    pool: float = DEFAULT_POOL_TIMEOUT,
) -> httpx.Timeout:
    """Return standardized httpx.Timeout with bounded connection, read, write, and pool durations."""
    return httpx.Timeout(
        connect=connect,
        read=read,
        write=write,
        pool=pool,
    )


class SafeStreamReader:
    """
    Safely streams and bounds HTTP response or byte streams up to a maximum cumulative byte limit.

    Protects against decompression bombs, slowloris byte exhaustion, and unbounded streaming responses
    by tracking cumulative read bytes and halting immediately when the configured budget is exceeded.
    """

    def __init__(
        self,
        response: httpx.Response | None = None,
        max_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        chunk_size: int = 8192,
    ) -> None:
        self.response = response
        self.max_bytes = max_bytes
        self.chunk_size = chunk_size
        self.bytes_read: int = 0

        if self.response is not None:
            cl_header = self.response.headers.get("content-length")
            if cl_header and cl_header.strip().isdigit():
                if int(cl_header.strip()) > self.max_bytes:
                    raise ResponseBodyTooLargeError(
                        f"Response Content-Length {cl_header} exceeds limit of {self.max_bytes} bytes"
                    )

    async def iter_bytes(
        self,
        stream: AsyncIterator[bytes] | None = None,
        chunk_size: int | None = None,
    ) -> AsyncIterator[bytes]:
        """Yield chunks while enforcing cumulative read byte limits."""
        size = chunk_size or self.chunk_size
        byte_stream = stream
        if byte_stream is None:
            if self.response is None:
                raise ValueError("No response or stream provided to SafeStreamReader")
            byte_stream = self.response.aiter_bytes(chunk_size=size)

        async for chunk in byte_stream:
            self.bytes_read += len(chunk)
            if self.bytes_read > self.max_bytes:
                raise ResponseBodyTooLargeError(
                    f"Response stream exceeded limit of {self.max_bytes} bytes (read {self.bytes_read} bytes)"
                )
            yield chunk

    async def read_all(
        self,
        stream: AsyncIterator[bytes] | None = None,
    ) -> bytes:
        """Accumulate entire stream content safely into bytes, raising ResponseBodyTooLargeError if exceeded."""
        body = bytearray()
        async for chunk in self.iter_bytes(stream=stream):
            body.extend(chunk)
        return bytes(body)

    async def __aenter__(self) -> SafeStreamReader:
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        pass


async def read_bounded_response_stream(
    response: httpx.Response,
    max_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    chunk_size: int = 8192,
) -> bytes:
    """Stream response content safely up to max_bytes, aborting if exceeded."""
    reader = SafeStreamReader(response=response, max_bytes=max_bytes, chunk_size=chunk_size)
    return await reader.read_all()


def create_safe_async_client(
    timeout: float | httpx.Timeout = DEFAULT_REQUEST_TIMEOUT,
    *,
    follow_redirects: bool = False,
    trust_env: bool = False,
    proxy: str | None = None,
    **kwargs,
) -> httpx.AsyncClient:
    """
    Create an httpx.AsyncClient configured with SafeAsyncHTTPTransport.

    By default, trust_env=False suppresses ambient environment proxy variables
    (such as HTTP_PROXY, HTTPS_PROXY, ALL_PROXY) to prevent unvetted traffic routing.
    If an explicit proxy is configured or passed, its destination is strictly validated.
    """
    if proxy is None:
        try:
            from app.core.config import get_settings
            settings = get_settings()
            proxy = settings.outbound_proxy_url
            if trust_env is False and settings.outbound_trust_env:
                trust_env = settings.outbound_trust_env
        except Exception:
            proxy = None

    if proxy is not None:
        validate_proxy_url(proxy)
        transport = SafeAsyncHTTPTransport(proxy=proxy, trust_env=trust_env)
        return httpx.AsyncClient(
            transport=transport,
            timeout=timeout,
            follow_redirects=follow_redirects,
            trust_env=trust_env,
            proxy=proxy,
            **kwargs,
        )

    transport = SafeAsyncHTTPTransport(trust_env=trust_env)
    return httpx.AsyncClient(
        transport=transport,
        timeout=timeout,
        follow_redirects=follow_redirects,
        trust_env=trust_env,
        **kwargs,
    )


async def safe_request(
    method: str,
    url: str,
    *,
    client: httpx.AsyncClient | None = None,
    follow_redirects: bool = True,
    max_redirects: int = 5,
    timeout: float | httpx.Timeout = DEFAULT_REQUEST_TIMEOUT,
    max_response_bytes: int | None = DEFAULT_MAX_RESPONSE_BYTES,
    **kwargs,
) -> httpx.Response:
    """
    Perform an outbound HTTP request with strict hop-by-hop redirect revalidation.

    Guarantees:
    - Every redirect target is normalized and validated against outbound IP policy.
    - Unsupported schemes (file, gopher, ftp, data) in Location headers are rejected.
    - Redirect loops and excessive chains are aborted at max_redirects.
    """
    current_url = url
    redirect_count = 0
    close_client = False

    if client is None:
        client = create_safe_async_client(timeout=timeout)
        close_client = True

    try:
        while True:
            parsed = urlparse(current_url)
            if parsed.scheme not in ("http", "https"):
                raise SafeRedirectError(
                    f"Unsupported scheme '{parsed.scheme}' in URL: {current_url}"
                )

            if not parsed.hostname:
                raise SafeRedirectError(f"Missing hostname in URL: {current_url}")

            response = await client.request(
                method=method,
                url=current_url,
                **kwargs,
            )

            if follow_redirects and response.status_code in (301, 302, 303, 307, 308) and "location" in response.headers:
                redirect_count += 1
                if redirect_count > max_redirects:
                    raise MaxRedirectsExceededError(
                        f"Maximum redirect hops ({max_redirects}) exceeded for {url}"
                    )

                raw_location = response.headers["location"]
                next_url = urljoin(current_url, raw_location)
                parsed_next = urlparse(next_url)

                if parsed_next.scheme not in ("http", "https"):
                    raise SafeRedirectError(
                        f"Redirect target uses prohibited scheme '{parsed_next.scheme}': {next_url}"
                    )

                if not parsed_next.hostname:
                    raise SafeRedirectError(f"Redirect target missing hostname: {next_url}")

                default_port = 443 if parsed_next.scheme == "https" else 80
                port = parsed_next.port or default_port
                resolve_public_target(parsed_next.hostname, port)

                current_url = next_url
                if response.status_code == 303:
                    method = "GET"
                continue

            if max_response_bytes is not None:
                cl_header = response.headers.get("content-length")
                if cl_header and cl_header.strip().isdigit():
                    if int(cl_header.strip()) > max_response_bytes:
                        raise ResponseBodyTooLargeError(
                            f"Response Content-Length {cl_header} exceeds limit of {max_response_bytes} bytes"
                        )
                if len(response.content) > max_response_bytes:
                    raise ResponseBodyTooLargeError(
                        f"Response body ({len(response.content)} bytes) exceeds limit of {max_response_bytes} bytes"
                    )

            return response
    finally:
        if close_client:
            await client.aclose()


@asynccontextmanager
async def safe_stream_request(
    method: str,
    url: str,
    *,
    client: httpx.AsyncClient | None = None,
    timeout: float | httpx.Timeout = DEFAULT_REQUEST_TIMEOUT,
    max_response_bytes: int | None = DEFAULT_MAX_RESPONSE_BYTES,
    **kwargs,
) -> AsyncIterator[httpx.Response]:
    """Perform a streaming outbound HTTP request with strict safe destination validation.

    Guarantees:
    - Pre-connection DNS evaluation and IP destination policy validation.
    - Response headers and status line are read without buffering response body.
    - Content-Length header is checked against max_response_bytes before streaming.
    - Exiting the context block immediately closes the response stream.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SafeRedirectError(f"Unsupported scheme '{parsed.scheme}' in URL: {url}")
    if not parsed.hostname:
        raise SafeRedirectError(f"Missing hostname in URL: {url}")

    default_port = 443 if parsed.scheme == "https" else 80
    port = parsed.port or default_port
    resolve_public_target(parsed.hostname, port)

    close_client = False
    if client is None:
        client = create_safe_async_client(timeout=timeout)
        close_client = True

    try:
        async with client.stream(
            method=method,
            url=url,
            **kwargs,
        ) as response:
            if max_response_bytes is not None:
                cl_header = response.headers.get("content-length")
                if cl_header and cl_header.strip().isdigit():
                    if int(cl_header.strip()) > max_response_bytes:
                        raise ResponseBodyTooLargeError(
                            f"Response Content-Length {cl_header} exceeds limit of {max_response_bytes} bytes"
                        )
            yield response
    finally:
        if close_client:
            await client.aclose()

