"""Policy tests for scoped WAF response-handling candidates."""
from __future__ import annotations

import pytest

from talisman.engine.scope import ScopeConfig, ScopeEnforcer
from talisman.modules.waf import bypass_engine


def _scope() -> ScopeEnforcer:
    return ScopeEnforcer(
        ScopeConfig(
            include=["example.com"],
            service_allowlist=[],
            max_concurrent_requests=2,
        )
    )


@pytest.mark.asyncio
async def test_waf_bypass_requires_explicit_scope(monkeypatch):
    class UnexpectedClient:
        def __init__(self, *args, **kwargs):
            raise AssertionError("HTTP client must not be created without scope")

    monkeypatch.setattr(bypass_engine, "TalismanHTTPClient", UnexpectedClient)
    result = await bypass_engine.run(target="https://example.com")

    assert result["error"] == "scope_enforcer_required"
    assert result["findings"] == []


@pytest.mark.asyncio
async def test_waf_not_blocked_response_is_candidate_not_confirmed_bypass(monkeypatch):
    observed = {}

    class Response:
        status_code = 200
        text = "Application response"
        
    class Client:
        def __init__(self, **kwargs):
            observed["scope"] = kwargs.get("scope")

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, *args, **kwargs):
            return Response()

    monkeypatch.setattr(bypass_engine, "TalismanHTTPClient", Client)
    monkeypatch.setattr(
        bypass_engine,
        "VENDOR_BYPASS_MAP",
        {"TestWAF": {"xss": ["<script>talisman()</script>"]}},
    )
    scope = _scope()

    result = await bypass_engine.run(
        target="https://example.com",
        scope=scope,
        waf="TestWAF",
        vuln_type="xss",
        param="q",
    )

    assert observed["scope"] is scope
    assert result["count"] == 0
    assert result["findings"] == []
    assert result["candidate_count"] == 1
    candidate = result["candidates"][0]
    assert candidate["passed"] is True
    assert candidate["not_blocked"] is True
    assert candidate["requires_application_verification"] is True
    assert result["confirmed_bypasses"] == 0
