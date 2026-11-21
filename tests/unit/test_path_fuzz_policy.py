"""Policy tests for scoped path discovery and candidate-only classification."""
from __future__ import annotations

import pytest

from talisman.engine.scope import ScopeConfig, ScopeEnforcer
from talisman.modules.fuzzer import path_fuzz


def _scope() -> ScopeEnforcer:
    return ScopeEnforcer(
        ScopeConfig(
            include=["example.com"],
            service_allowlist=[],
            max_concurrent_requests=2,
        )
    )


@pytest.mark.asyncio
async def test_path_fuzzer_requires_explicit_scope(monkeypatch):
    class UnexpectedClient:
        def __init__(self, *args, **kwargs):
            raise AssertionError("HTTP client must not be created without scope")

    monkeypatch.setattr(path_fuzz, "TalismanHTTPClient", UnexpectedClient)
    result = await path_fuzz.run(target="https://example.com")

    assert result["error"] == "scope_enforcer_required"
    assert result["findings"] == []


@pytest.mark.asyncio
async def test_path_fuzzer_passes_exact_scope_and_does_not_confirm_status_only(monkeypatch):
    observed = {}

    class Client:
        def __init__(self, **kwargs):
            observed["scope"] = kwargs.get("scope")

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

    async def fake_probe(base_url, path, client):
        return {
            "path": path,
            "url": base_url.rstrip("/") + "/" + path,
            "status": 200,
            "size": 128,
            "content_type": "text/html",
            "redirect": "",
        }

    class Session:
        async def add_finding(self, *args, **kwargs):
            raise AssertionError("Path status alone must never create a confirmed finding")

    monkeypatch.setattr(path_fuzz, "TalismanHTTPClient", Client)
    monkeypatch.setattr(path_fuzz, "_probe_path", fake_probe)
    monkeypatch.setattr(path_fuzz, "BUILT_IN_PATHS", [".env"])
    scope = _scope()

    result = await path_fuzz.run(
        target="https://example.com",
        session=Session(),
        scope=scope,
        extensions=[],
        threads=100,
    )

    assert observed["scope"] is scope
    assert result["count"] == 1
    assert result["findings"] == []
    assert result["confirmed_findings"] == 0
    assert result["candidates"][0]["requires_content_verification"] is True


@pytest.mark.asyncio
async def test_path_fuzzer_rejects_nonpositive_thread_count_before_client(monkeypatch):
    class UnexpectedClient:
        def __init__(self, *args, **kwargs):
            raise AssertionError("invalid concurrency must fail before client creation")

    monkeypatch.setattr(path_fuzz, "TalismanHTTPClient", UnexpectedClient)
    result = await path_fuzz.run(
        target="https://example.com",
        scope=_scope(),
        threads=0,
    )

    assert result["error"] == "threads must be a positive integer"
