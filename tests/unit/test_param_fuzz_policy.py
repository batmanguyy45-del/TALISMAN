"""Security tests for parameter-fuzzer method and scope policy."""
from __future__ import annotations

import pytest

from talisman.engine.scope import ScopeConfig, ScopeEnforcer
from talisman.modules.fuzzer import param_fuzz


def _scope(*, allow_writes=False, avoid_writes=True, avoid_destructive=True):
    return ScopeEnforcer(
        ScopeConfig(
            include=["example.com"],
            service_allowlist=[],
            allow_state_changing_requests=allow_writes,
            avoid_writes=avoid_writes,
            avoid_destructive=avoid_destructive,
            max_concurrent_requests=2,
        )
    )


@pytest.mark.asyncio
async def test_param_fuzzer_requires_explicit_scope(monkeypatch):
    class MustNotCreateClient:
        def __init__(self, *args, **kwargs):
            raise AssertionError("client must not be created without scope")

    monkeypatch.setattr(param_fuzz, "TalismanHTTPClient", MustNotCreateClient)
    result = await param_fuzz.run(target="https://example.com")

    assert result["error"] == "scope_enforcer_required"
    assert result["found"] == []


@pytest.mark.asyncio
async def test_param_fuzzer_defaults_to_get_only_and_passes_scope(monkeypatch):
    observed = {}

    class Response:
        status_code = 200
        content = b"baseline"

    class Client:
        def __init__(self, *args, **kwargs):
            observed["scope"] = kwargs.get("scope")

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, *args, **kwargs):
            return Response()

    async def probe(url, param, method, client, baseline_status, baseline_size):
        observed.setdefault("methods", []).append(method)
        return None

    monkeypatch.setattr(param_fuzz, "TalismanHTTPClient", Client)
    monkeypatch.setattr(param_fuzz, "_probe_param", probe)
    monkeypatch.setattr(param_fuzz, "COMMON_PARAMS", ["id", "q"])

    scope = _scope()
    result = await param_fuzz.run(target="https://example.com", scope=scope)

    assert observed["scope"] is scope
    assert set(observed["methods"]) == {"GET"}
    assert result["methods_run"] == ["GET"]
    assert result["skipped_methods"] == []


@pytest.mark.asyncio
async def test_param_fuzzer_post_requires_destructive_scope_permission(monkeypatch):
    observed = {}

    class Response:
        status_code = 200
        content = b"baseline"

    class Client:
        def __init__(self, *args, **kwargs):
            observed["scope"] = kwargs.get("scope")

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, *args, **kwargs):
            return Response()

    async def probe(url, param, method, client, baseline_status, baseline_size):
        observed.setdefault("methods", []).append(method)
        return None

    monkeypatch.setattr(param_fuzz, "TalismanHTTPClient", Client)
    monkeypatch.setattr(param_fuzz, "_probe_param", probe)
    monkeypatch.setattr(param_fuzz, "COMMON_PARAMS", ["id"])

    result = await param_fuzz.run(
        target="https://example.com",
        scope=_scope(allow_writes=True, avoid_writes=False, avoid_destructive=True),
        methods="GET,POST",
    )

    assert observed["methods"] == ["GET"]
    assert result["methods_run"] == ["GET"]
    assert result["skipped_methods"] == ["POST"]


@pytest.mark.asyncio
async def test_param_fuzzer_post_runs_only_after_explicit_destructive_opt_in(monkeypatch):
    observed = {}

    class Response:
        status_code = 200
        content = b"baseline"

    class Client:
        def __init__(self, *args, **kwargs):
            observed["scope"] = kwargs.get("scope")

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, *args, **kwargs):
            return Response()

    async def probe(url, param, method, client, baseline_status, baseline_size):
        observed.setdefault("methods", []).append(method)
        return None

    monkeypatch.setattr(param_fuzz, "TalismanHTTPClient", Client)
    monkeypatch.setattr(param_fuzz, "_probe_param", probe)
    monkeypatch.setattr(param_fuzz, "COMMON_PARAMS", ["id"])

    scope = _scope(allow_writes=True, avoid_writes=False, avoid_destructive=False)
    result = await param_fuzz.run(
        target="https://example.com",
        scope=scope,
        methods="GET,POST",
    )

    assert set(observed["methods"]) == {"GET", "POST"}
    assert result["methods_run"] == ["GET", "POST"]
    assert result["skipped_methods"] == []


@pytest.mark.asyncio
async def test_param_fuzzer_rejects_unknown_methods_without_sending_requests(monkeypatch):
    class MustNotCreateClient:
        def __init__(self, *args, **kwargs):
            raise AssertionError("unsupported method must fail before client creation")

    monkeypatch.setattr(param_fuzz, "TalismanHTTPClient", MustNotCreateClient)
    result = await param_fuzz.run(
        target="https://example.com",
        scope=_scope(),
        methods="GET,DELETE",
    )

    assert "unsupported fuzz methods" in result["error"]
