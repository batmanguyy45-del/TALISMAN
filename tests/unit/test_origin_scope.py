"""Regression tests for explicitly scoped CDN origin discovery."""
from __future__ import annotations

import pytest

from talisman.engine.scope import ScopeConfig, ScopeEnforcer
from talisman.modules.waf.vendors import cloudflare


class _FakeClient:
    def __init__(self, *args, **kwargs):
        self.scope = kwargs.get("scope")

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


@pytest.mark.asyncio
async def test_origin_discovery_requires_scope(monkeypatch):
    def must_not_discover(*args, **kwargs):
        raise AssertionError("Origin discovery must fail before external lookups without scope")

    monkeypatch.setattr(cloudflare, "TalismanHTTPClient", must_not_discover)
    result = await cloudflare.find_origin("https://example.com")

    assert result["error"] == "scope_enforcer_required"
    assert result["candidates"] == []
    assert result["confirmed_origins"] == []


@pytest.mark.asyncio
async def test_out_of_scope_origin_ip_is_never_verified(monkeypatch):
    scope = ScopeEnforcer(
        ScopeConfig(include=["example.com"], service_allowlist=[])
    )
    monkeypatch.setattr(cloudflare, "TalismanHTTPClient", _FakeClient)

    async def fake_crtsh(domain, client):
        return ["203.0.113.45"]

    async def fake_mx(domain, scoped):
        return []

    async def verification_must_not_run(domain, ip, client):
        raise AssertionError("Discovered IP must not be contacted unless explicitly in scope")

    monkeypatch.setattr(cloudflare, "_crtsh_ips", fake_crtsh)
    monkeypatch.setattr(cloudflare, "_mx_ips", fake_mx)
    monkeypatch.setattr(cloudflare, "_verify_origin", verification_must_not_run)

    result = await cloudflare.find_origin(
        "https://example.com",
        scope=scope,
    )

    assert result["candidates"] == ["203.0.113.45"]
    assert result["verified_candidates"] == []
    assert result["out_of_scope_candidates"] == ["203.0.113.45"]
    assert result["confirmed_origins"] == []


@pytest.mark.asyncio
async def test_explicitly_scoped_origin_ip_can_be_verified(monkeypatch):
    scope = ScopeEnforcer(
        ScopeConfig(
            include=["example.com", "203.0.113.45/32"],
            service_allowlist=[],
        )
    )
    monkeypatch.setattr(cloudflare, "TalismanHTTPClient", _FakeClient)

    async def fake_crtsh(domain, client):
        return ["203.0.113.45"]

    async def fake_mx(domain, scoped):
        return []

    async def fake_verification(domain, ip, client):
        assert domain == "example.com"
        assert ip == "203.0.113.45"
        return True

    monkeypatch.setattr(cloudflare, "_crtsh_ips", fake_crtsh)
    monkeypatch.setattr(cloudflare, "_mx_ips", fake_mx)
    monkeypatch.setattr(cloudflare, "_verify_origin", fake_verification)

    result = await cloudflare.find_origin(
        "https://example.com",
        scope=scope,
    )

    assert result["verified_candidates"] == ["203.0.113.45"]
    assert result["out_of_scope_candidates"] == []
    assert result["responding_candidates"] == ["203.0.113.45"]
    assert result["confirmed_origins"] == []
    assert result["origin_found"] is False
    assert result["requires_manual_origin_confirmation"] is True
