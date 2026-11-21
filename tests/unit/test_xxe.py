"""Tests for evidence-led XXE and unique OAST callback handling."""
from __future__ import annotations

import pytest

from talisman.engine.scope import ScopeConfig, ScopeEnforcer
from talisman.modules.scanner import xxe


def _destructive_scope():
    return ScopeEnforcer(
        ScopeConfig(
            include=["example.com"],
            service_allowlist=[],
            allow_state_changing_requests=True,
            avoid_writes=False,
            avoid_destructive=False,
        )
    )


class _FakeHTTPClient:
    def __init__(self, *args, **kwargs):
        assert kwargs.get("scope") is not None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


class _FakeOASTClient:
    def __init__(self, server):
        self.server = server
        self.generated = False
        self.polled = False

    def get_payload_url(self, prefix=""):
        assert prefix == "xxe"
        self.generated = True
        return f"http://xxe-unique-token.{self.server}/"

    def get_xxe_payloads(self, token):
        assert token == f"xxe-unique-token.{self.server}"
        return [
            f'<!DOCTYPE r [<!ENTITY xxe SYSTEM "http://{token}/xxe">]><r>&xxe;</r>'
        ]

    async def poll(self, token, timeout=30):
        assert token == f"xxe-unique-token.{self.server}"
        assert timeout == 10
        self.polled = True
        return [{
            "type": "http",
            "source_ip": "93.184.216.34",
            "timestamp": "2026-11-21T12:00:00Z",
            "raw": "GET /xxe HTTP/1.1\\r\\nHost: xxe-unique-token.oast.example",
        }]


@pytest.mark.asyncio
async def test_xxe_blind_callback_is_an_impact_pending_candidate(monkeypatch):
    fake_oast = _FakeOASTClient("oast.example")

    async def validated_domain(value):
        assert value == "oast.example"
        return value

    async def no_reflected_disclosure(*args, **kwargs):
        return None

    monkeypatch.setattr(xxe, "validate_public_oast_domain", validated_domain)
    monkeypatch.setattr(xxe, "OASTClient", lambda server: fake_oast)
    monkeypatch.setattr(xxe, "TalismanHTTPClient", _FakeHTTPClient)
    monkeypatch.setattr(xxe, "_test_xxe_endpoint", no_reflected_disclosure)

    class Session:
        def __init__(self):
            self.saved = []

        async def add_finding(self, *args, **kwargs):
            self.saved.append((args, kwargs))

    session = Session()
    result = await xxe.run(
        target="https://example.com",
        scope=_destructive_scope(),
        oast_domain="oast.example",
        session=session,
    )

    assert fake_oast.generated is True
    assert fake_oast.polled is True
    assert result["findings"] == []
    assert result["count"] == 0
    assert result["candidate_count"] == 1
    assert result["candidates"][0]["indicator"] == "oast_callback"
    assert result["candidates"][0]["confidence"] == "confirmed_interaction"
    assert result["candidates"][0]["requires_impact_validation"] is True
    assert result["oast_verification_performed"] is True
    assert session.saved == []


@pytest.mark.asyncio
async def test_xxe_does_not_claim_oast_verification_without_callback(monkeypatch):
    async def no_reflected_disclosure(*args, **kwargs):
        return None

    monkeypatch.setattr(xxe, "TalismanHTTPClient", _FakeHTTPClient)
    monkeypatch.setattr(xxe, "_test_xxe_endpoint", no_reflected_disclosure)

    result = await xxe.run(
        target="https://example.com",
        scope=_destructive_scope(),
    )

    assert result["findings"] == []
    assert result["candidates"] == []
    assert result["oast_callbacks"] == 0
    assert result["oast_verification_performed"] is False


@pytest.mark.asyncio
async def test_xxe_requires_explicit_scope_and_destructive_permission():
    missing_scope = await xxe.run(target="https://example.com")
    assert missing_scope["error"] == "scope_enforcer_required"

    safe_scope = ScopeEnforcer(
        ScopeConfig(include=["example.com"], service_allowlist=[])
    )
    blocked = await xxe.run(
        target="https://example.com",
        scope=safe_scope,
    )
    assert blocked["skipped"] is True
    assert blocked["findings"] == []
