"""Tests for safe HTTP behavior and central scope enforcement."""
from __future__ import annotations

import httpx
import pytest
from ipaddress import ip_address

from talisman.engine.scope import ScopeConfig, ScopeEnforcer, ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient


def _mock_client(scope, handler, **kwargs):
    async def allow_test_destination(url, method="GET"):
        scope.assert_request_allowed(url, method)
        return (ip_address("93.184.216.34"),)

    scope.resolve_network_destination = allow_test_destination
    client = TalismanHTTPClient(scope=scope, **kwargs)
    client._build_client = lambda: httpx.AsyncClient(
        transport=httpx.MockTransport(handler)
    )
    return client


@pytest.mark.asyncio
async def test_out_of_scope_request_is_blocked_before_network():
    calls = []

    async def handler(request):
        calls.append(request)
        return httpx.Response(200, request=request)

    scope = ScopeEnforcer(ScopeConfig(include=["example.com"], service_allowlist=[]))
    async with _mock_client(scope, handler) as client:
        with pytest.raises(ScopeViolationError):
            await client.get("https://attacker.test/")

    assert calls == []


@pytest.mark.asyncio
async def test_write_methods_require_explicit_scope_opt_in():
    calls = []

    async def handler(request):
        calls.append(request)
        return httpx.Response(200, request=request)

    scope = ScopeEnforcer(ScopeConfig(include=["example.com"], service_allowlist=[]))
    async with _mock_client(scope, handler) as client:
        with pytest.raises(ScopeViolationError, match="POST blocked"):
            await client.post("https://example.com/profile", json={"name": "test"})

    assert calls == []


@pytest.mark.asyncio
async def test_destructive_methods_remain_blocked_after_write_opt_in():
    calls = []

    async def handler(request):
        calls.append(request)
        return httpx.Response(200, request=request)

    scope = ScopeEnforcer(ScopeConfig(
        include=["example.com"],
        service_allowlist=[],
        allow_state_changing_requests=True,
        avoid_destructive=True,
    ))
    async with _mock_client(scope, handler) as client:
        with pytest.raises(ScopeViolationError, match="DELETE blocked"):
            await client.delete("https://example.com/account")

    assert calls == []


@pytest.mark.asyncio
async def test_allowed_write_requires_both_scope_opt_in_and_scope_membership():
    calls = []

    async def handler(request):
        calls.append(request)
        return httpx.Response(204, request=request)

    scope = ScopeEnforcer(ScopeConfig(
        include=["example.com"],
        service_allowlist=[],
        allow_state_changing_requests=True,
        avoid_writes=False,
    ))
    async with _mock_client(scope, handler) as client:
        response = await client.post("https://example.com/profile", json={"name": "test"})

    assert response.status_code == 204
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_redirect_to_out_of_scope_host_is_blocked_before_second_request():
    calls = []

    async def handler(request):
        calls.append(request)
        return httpx.Response(
            302,
            headers={"Location": "https://attacker.test/collect"},
            request=request,
        )

    scope = ScopeEnforcer(ScopeConfig(include=["example.com"], service_allowlist=[]))
    async with _mock_client(scope, handler, follow_redirects=True) as client:
        with pytest.raises(ScopeViolationError):
            await client.get("https://example.com/start")

    assert len(calls) == 1


@pytest.mark.asyncio
async def test_credentials_are_not_forwarded_across_allowed_origin_redirect():
    seen_headers = []

    async def handler(request):
        seen_headers.append(dict(request.headers))
        if request.url.host == "example.com":
            return httpx.Response(
                302,
                headers={"Location": "https://docs.example.net/next"},
                request=request,
            )
        return httpx.Response(200, request=request)

    scope = ScopeEnforcer(ScopeConfig(
        include=["example.com"],
        service_allowlist=["docs.example.net"],
    ))
    async with _mock_client(scope, handler, follow_redirects=True) as client:
        response = await client.get(
            "https://example.com/start",
            headers={"Authorization": "Bearer secret", "Cookie": "sid=secret"},
        )

    assert response.status_code == 200
    assert len(seen_headers) == 2
    assert seen_headers[0].get("authorization") == "Bearer secret"
    assert "authorization" not in seen_headers[1]
    assert "cookie" not in seen_headers[1]


def test_secure_http_defaults():
    client = TalismanHTTPClient()
    assert client.verify_ssl is True
    assert client.follow_redirects is False
    assert client.rotate_ua is False



@pytest.mark.asyncio
async def test_host_header_is_available_for_authorized_host_header_testing():
    seen = []

    async def handler(request):
        seen.append(request.headers.get("host"))
        return httpx.Response(200, request=request)

    scope = ScopeEnforcer(ScopeConfig(include=["example.com"], service_allowlist=[]))
    async with _mock_client(scope, handler) as client:
        await client.get("https://example.com/", headers={"Host": "controlled.example"})

    assert seen == ["controlled.example"]


def test_header_injection_is_rejected():
    with pytest.raises(ValueError):
        TalismanHTTPClient(headers={"X-Test": "ok\r\nInjected: yes"})


@pytest.mark.asyncio
async def test_cross_origin_redirect_drops_all_custom_headers():
    seen = []

    async def handler(request):
        seen.append(dict(request.headers))
        if request.url.host == "example.com":
            return httpx.Response(
                302,
                headers={"Location": "https://docs.example.net/next"},
                request=request,
            )
        return httpx.Response(200, request=request)

    scope = ScopeEnforcer(ScopeConfig(
        include=["example.com"],
        service_allowlist=["docs.example.net"],
    ))
    async with _mock_client(scope, handler, follow_redirects=True) as client:
        response = await client.get(
            "https://example.com/start",
            headers={
                "Authorization": "Bearer secret",
                "Cookie": "sid=secret",
                "X-API-Key": "secret",
                "Host": "example.com",
            },
        )

    assert response.status_code == 200
    assert len(seen) == 2
    for name in ("authorization", "cookie", "x-api-key"):
        assert name not in seen[1]
    assert seen[1].get("host") == "docs.example.net"



@pytest.mark.asyncio
async def test_http_client_fails_closed_without_active_or_explicit_scope():
    calls = []

    async def handler(request):
        calls.append(request)
        return httpx.Response(200, request=request)

    client = TalismanHTTPClient()
    client._build_client = lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler))
    async with client:
        with pytest.raises(ScopeViolationError, match="no active target scope"):
            await client.get("https://example.com/")

    assert calls == []



def test_hackerone_username_header_rejects_crlf(monkeypatch):
    from talisman.utils.http_client import _load_extra_headers

    monkeypatch.setenv("TALISMAN_EXTRA_HEADERS", "")
    monkeypatch.setenv("TALISMAN_H1_USERNAME", "researcher\r\nX-Injected: yes")

    with pytest.raises(ValueError, match="line break"):
        _load_extra_headers()



@pytest.mark.asyncio
async def test_pinned_backend_substitutes_only_the_validated_origin_host():
    from talisman.utils.http_client import (
        _PINNED_DESTINATION,
        _PinnedNetworkBackend,
    )

    class FakeBackend:
        def __init__(self):
            self.calls = []

        async def connect_tcp(
            self,
            host,
            port,
            timeout=None,
            local_address=None,
            socket_options=None,
        ):
            self.calls.append((host, port))
            return "stream"

        async def connect_unix_socket(self, path, timeout=None, socket_options=None):
            return "unix-stream"

        async def sleep(self, seconds):
            return None

    backend = FakeBackend()
    pinned_backend = _PinnedNetworkBackend(backend)
    token = _PINNED_DESTINATION.set(("example.com", "93.184.216.34"))
    try:
        await pinned_backend.connect_tcp("example.com", 443)
        await pinned_backend.connect_tcp("other.example", 443)
    finally:
        _PINNED_DESTINATION.reset(token)

    assert backend.calls == [
        ("93.184.216.34", 443),
        ("other.example", 443),
    ]


@pytest.mark.asyncio
async def test_explicit_proxy_requires_unpinned_proxy_opt_in(monkeypatch):
    from ipaddress import ip_address

    from talisman.engine.scope import ScopeConfig, ScopeEnforcer, ScopeViolationError

    scope = ScopeEnforcer(
        ScopeConfig(include=["example.com"], service_allowlist=[])
    )

    async def approved_addresses(url, method="GET"):
        scope.assert_request_allowed(url, method)
        return (ip_address("93.184.216.34"),)

    scope.resolve_network_destination = approved_addresses
    monkeypatch.delenv("TALISMAN_ALLOW_UNPINNED_PROXY", raising=False)

    client = TalismanHTTPClient(
        scope=scope,
        proxy="http://127.0.0.1:8080",
    )
    client._build_client = lambda: httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, request=request)
        )
    )

    async with client:
        with pytest.raises(ScopeViolationError, match="proxy resolves the target"):
            await client.get("https://example.com/")


@pytest.mark.asyncio
async def test_http_client_rejects_declared_oversized_response():
    from talisman.utils.http_client import ResponseTooLargeError

    async def handler(request):
        return httpx.Response(
            200,
            headers={"Content-Length": "6"},
            content=b"123456",
            request=request,
        )

    scope = ScopeEnforcer(ScopeConfig(include=["example.com"], service_allowlist=[]))
    async with _mock_client(scope, handler, max_response_bytes=5) as client:
        with pytest.raises(ResponseTooLargeError, match="declared 6 bytes"):
            await client.get("https://example.com/large")


@pytest.mark.asyncio
async def test_http_client_caps_decompressed_response_size():
    import gzip

    from talisman.utils.http_client import ResponseTooLargeError

    compressed = gzip.compress(b"A" * 4096)

    async def handler(request):
        return httpx.Response(
            200,
            headers={
                "Content-Encoding": "gzip",
                "Content-Length": str(len(compressed)),
            },
            content=compressed,
            request=request,
        )

    scope = ScopeEnforcer(ScopeConfig(include=["example.com"], service_allowlist=[]))
    async with _mock_client(scope, handler, max_response_bytes=512) as client:
        with pytest.raises(ResponseTooLargeError, match="decoded body limit"):
            await client.get("https://example.com/compressed")


@pytest.mark.asyncio
async def test_http_client_allows_response_at_configured_limit():
    async def handler(request):
        return httpx.Response(200, content=b"12345", request=request)

    scope = ScopeEnforcer(ScopeConfig(include=["example.com"], service_allowlist=[]))
    async with _mock_client(scope, handler, max_response_bytes=5) as client:
        response = await client.get("https://example.com/small")

    assert response.status_code == 200
    assert response.content == b"12345"


@pytest.mark.asyncio
async def test_http_client_enforces_total_response_deadline():
    import asyncio

    async def handler(request):
        await asyncio.sleep(0.05)
        return httpx.Response(200, content=b"late", request=request)

    scope = ScopeEnforcer(ScopeConfig(include=["example.com"], service_allowlist=[]))
    async with _mock_client(scope, handler, max_retries=1) as client:
        with pytest.raises(TimeoutError):
            await client.get("https://example.com/slow", timeout=0.005)


def test_http_client_rejects_unbounded_response_configuration():
    from talisman.utils.http_client import MAX_ALLOWED_RESPONSE_BYTES

    for invalid in (0, -1, True, 1.5, MAX_ALLOWED_RESPONSE_BYTES + 1):
        with pytest.raises(ValueError, match="max_response_bytes"):
            TalismanHTTPClient(max_response_bytes=invalid)


@pytest.mark.asyncio
async def test_http_client_uses_assessment_wide_concurrency_limit():
    import asyncio

    active = 0
    peak_active = 0

    async def handler(request):
        nonlocal active, peak_active
        active += 1
        peak_active = max(peak_active, active)
        await asyncio.sleep(0.12)
        active -= 1
        return httpx.Response(200, request=request)

    scope = ScopeEnforcer(
        ScopeConfig(
            include=["example.com"],
            service_allowlist=[],
            max_requests_per_second=20,
            max_concurrent_requests=1,
        )
    )
    async with _mock_client(scope, handler, max_retries=1) as client:
        await asyncio.gather(
            client.get("https://example.com/one"),
            client.get("https://example.com/two"),
        )

    assert peak_active == 1
