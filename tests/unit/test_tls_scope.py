"""Tests that raw TLS sockets enforce scope against the actual TLS URL."""
from __future__ import annotations

import pytest

from talisman.engine.scope import ScopeConfig, ScopeEnforcer
from talisman.modules.network import ssl_tls


@pytest.mark.asyncio
async def test_tls_audit_does_not_use_https_when_scope_only_allows_http(monkeypatch):
    scope = ScopeEnforcer(
        ScopeConfig(
            include=["http://example.com"],
            service_allowlist=[],
        )
    )
    attempted_resolution = []
    attempted_socket = []

    original_resolve = scope.resolve_network_destination

    async def record_resolution(target, method="GET"):
        attempted_resolution.append(target)
        return await original_resolve(target, method)

    def forbidden_socket(*args, **kwargs):
        attempted_socket.append((args, kwargs))
        raise AssertionError("Out-of-scope TLS socket must never be opened")

    monkeypatch.setattr(scope, "resolve_network_destination", record_resolution)
    monkeypatch.setattr(ssl_tls, "_get_cert_info", forbidden_socket)

    result = await ssl_tls.run(target="http://example.com", scope=scope)

    assert attempted_resolution == ["https://example.com/"]
    assert attempted_socket == []
    assert result["findings"] == []
    assert result["error"]

@pytest.mark.asyncio
async def test_tls_audit_returns_error_for_out_of_range_url_port():
    scope = ScopeEnforcer(
        ScopeConfig(include=["example.com"], service_allowlist=[])
    )

    result = await ssl_tls.run(
        target="https://example.com:99999",
        scope=scope,
    )

    assert result["findings"] == []
    assert result["error"].startswith("invalid_target:")

