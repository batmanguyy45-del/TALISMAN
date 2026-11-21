"""Tests for safe HTTP behavior and central scope enforcement."""
from __future__ import annotations

import httpx
import pytest

from talisman.engine.scope import ScopeConfig, ScopeEnforcer, ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient


def _mock_client(scope, handler, **kwargs):
    client = TalismanHTTPClient(scope=scope, **kwargs)
    client._build_client = lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler))
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
        return httpx.Response(302, headers={"Location": "https://attacker.test/collect"}, request=request)

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
            return httpx.Response(302, headers={"Location": "https://docs.example.net/next"}, request=request)
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
        TalismanHTTPClient(headers={"X-Test": "ok\\r\\nInjected: yes"})


@pytest.mark.asyncio
async def test_cross_origin_redirect_drops_all_custom_headers():
    seen = []

    async def handler(request):
        seen.append(dict(request.headers))
        if request.url.host == "example.com":
            return httpx.Response(302, headers={"Location": "https://docs.example.net/next"}, request=request)
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
