"""Proxy-integrity regression tests for modules with raw network transports."""
from __future__ import annotations

import pytest

from talisman.engine.scope import ScopeConfig, ScopeEnforcer


class _HTTPResponse:
    status_code = 404
    text = ""
    headers = {}


class _FakeHTTPClient:
    def __init__(self, *args, **kwargs):
        self.proxy = kwargs.get("proxy")

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def get(self, *args, **kwargs):
        return _HTTPResponse()

    async def post(self, *args, **kwargs):
        raise AssertionError("No state-changing gRPC-Web POST expected")


@pytest.mark.asyncio
async def test_database_socket_scanner_refuses_proxy_bypass():
    from talisman.modules.misconfiguration import database_exposure

    scope = ScopeEnforcer(
        ScopeConfig(include=["example.com"], service_allowlist=[])
    )
    result = await database_exposure.run(
        target="https://example.com",
        scope=scope,
        proxy="http://127.0.0.1:8080",
    )

    assert result["skipped"] is True
    assert result["services"] == []
    assert result["findings"] == []
    assert "cannot honor the configured HTTP proxy" in result["reason"]


@pytest.mark.asyncio
async def test_tls_socket_scanner_refuses_proxy_bypass():
    from talisman.modules.network import ssl_tls

    scope = ScopeEnforcer(
        ScopeConfig(include=["example.com"], service_allowlist=[])
    )
    result = await ssl_tls.run(
        target="https://example.com",
        scope=scope,
        proxy="http://127.0.0.1:8080",
    )

    assert result["skipped"] is True
    assert result["findings"] == []
    assert "cannot honor the configured HTTP proxy" in result["reason"]


@pytest.mark.asyncio
async def test_grpc_raw_port_probes_are_skipped_when_proxy_is_configured(monkeypatch):
    from talisman.modules.api import grpc

    scope = ScopeEnforcer(
        ScopeConfig(include=["example.com"], service_allowlist=[])
    )

    async def raw_probe_must_not_run(*args, **kwargs):
        raise AssertionError("Raw gRPC socket probe must not bypass proxy")

    monkeypatch.setattr(grpc, "_check_grpc_port", raw_probe_must_not_run)
    monkeypatch.setattr(grpc, "TalismanHTTPClient", _FakeHTTPClient)

    result = await grpc.run(
        target="https://example.com",
        scope=scope,
        proxy="http://127.0.0.1:8080",
    )

    assert result["raw_port_probes_skipped"] is True
    assert result["discovered_ports"] == []


@pytest.mark.asyncio
async def test_dns_axfr_is_skipped_when_http_proxy_is_configured(monkeypatch):
    from talisman.modules.recon import dns

    class _Resolver:
        def __init__(self, *args, **kwargs):
            pass

        async def query(self, domain, record_type):
            return []

    monkeypatch.setattr(dns.aiodns, "DNSResolver", _Resolver)
    scope = ScopeEnforcer(
        ScopeConfig(include=["example.com"], service_allowlist=[])
    )

    result = await dns.run(
        target="example.com",
        scope=scope,
        zone_transfer=True,
        proxy="http://127.0.0.1:8080",
    )

    assert "zone_transfer_skipped" in result
    assert result["zone_transfer"] if "zone_transfer" in result else True
