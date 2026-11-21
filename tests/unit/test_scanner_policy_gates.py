"""Regression tests for scanner scope, write gates and candidate-only outputs."""
from __future__ import annotations

import pytest

from talisman.engine.scope import ScopeConfig, ScopeEnforcer


def _scope(*, allow_writes=False, avoid_writes=True, avoid_destructive=True):
    return ScopeEnforcer(
        ScopeConfig(
            include=["example.com"],
            service_allowlist=[],
            allow_state_changing_requests=allow_writes,
            avoid_writes=avoid_writes,
            avoid_destructive=avoid_destructive,
        )
    )


class _Response:
    def __init__(self, headers=None, text=""):
        self.headers = headers or {}
        self.text = text
        self.content = text.encode()


class _FakeClient:
    def __init__(self, *args, **kwargs):
        assert kwargs.get("scope") is not None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def get(self, *args, **kwargs):
        return _Response()

    async def post(self, *args, **kwargs):
        raise AssertionError("A POST was sent without destructive permission")


@pytest.mark.asyncio
async def test_xss_uses_only_get_without_destructive_permission(monkeypatch):
    from talisman.modules.scanner import xss

    seen = []

    async def fake_test(url, param, method, client, waf_bypass):
        seen.append(method)
        return None

    monkeypatch.setattr(xss, "_test_param", fake_test)
    monkeypatch.setattr(xss, "TalismanHTTPClient", _FakeClient)

    result = await xss.run("https://example.com/?q=hello", scope=_scope())

    assert seen == ["GET"]
    assert result["findings"] == []
    assert result["skipped_methods"] == ["POST"]


@pytest.mark.asyncio
async def test_sqli_uses_only_get_without_destructive_permission(monkeypatch):
    from talisman.modules.scanner import sqli

    seen = []

    async def fake_error(url, param, method, client):
        seen.append(method)
        if method == "GET":
            return {"technique": "error_based", "evidence": "synthetic test"}
        return None

    monkeypatch.setattr(sqli, "_test_error_based", fake_error)
    monkeypatch.setattr(sqli, "TalismanHTTPClient", _FakeClient)

    result = await sqli.run(
        "https://example.com/?id=1",
        scope=_scope(),
        techniques=["error"],
    )

    assert seen == ["GET"]
    assert result["findings"] == []
    assert result["candidate_count"] == 1
    assert result["skipped_methods"] == ["POST"]


@pytest.mark.asyncio
async def test_ssrf_disables_post_payloads_without_destructive_permission(monkeypatch):
    from talisman.modules.scanner import ssrf

    observed = []

    async def fake_test(url, param, client, oast_domain, **kwargs):
        observed.append(kwargs.get("allow_post_probes"))
        return None

    monkeypatch.setattr(ssrf, "_test_ssrf_param", fake_test)
    monkeypatch.setattr(ssrf, "TalismanHTTPClient", _FakeClient)

    result = await ssrf.run("https://example.com", scope=_scope())

    assert observed
    assert not any(observed)
    assert result["post_probes_enabled"] is False
    assert result["findings"] == []


@pytest.mark.asyncio
async def test_ssti_uses_only_get_without_destructive_permission(monkeypatch):
    from talisman.modules.scanner import ssti

    seen = []

    async def fake_test(url, param, method, client):
        seen.append(method)
        return None

    monkeypatch.setattr(ssti, "_test_param", fake_test)
    monkeypatch.setattr(ssti, "TalismanHTTPClient", _FakeClient)

    result = await ssti.run("https://example.com/?name=alice", scope=_scope())

    assert seen == ["GET"]
    assert result["findings"] == []
    assert result["skipped_methods"] == ["POST"]


@pytest.mark.asyncio
async def test_lfi_requires_scope_before_any_http_request():
    from talisman.modules.scanner import lfi_rfi

    result = await lfi_rfi.run("https://example.com/?file=home")

    assert result["error"] == "scope_enforcer_required"
    assert result["findings"] == []


@pytest.mark.asyncio
async def test_headers_are_observations_not_confirmed_findings(monkeypatch):
    from talisman.modules.scanner import headers

    monkeypatch.setattr(headers, "TalismanHTTPClient", _FakeClient)
    result = await headers.run("https://example.com", scope=_scope())

    assert result["findings"] == []
    assert result["count"] == 0
    assert result["observation_count"] >= 1


@pytest.mark.asyncio
async def test_cors_credentialed_origin_is_candidate_not_confirmed_finding(monkeypatch):
    from talisman.modules.scanner import cors

    async def fake_origin(url, label, origin, client):
        if label == "arbitrary_origin":
            return {
                "label": label,
                "origin_sent": origin,
                "acao": origin,
                "acac": "true",
                "credentials": True,
                "severity": "critical",
            }
        if label == "null_origin":
            return {
                "label": label,
                "origin_sent": origin,
                "acao": origin,
                "acac": "",
                "credentials": False,
                "severity": "medium",
            }
        return None

    monkeypatch.setattr(cors, "_test_origin", fake_origin)
    monkeypatch.setattr(cors, "TalismanHTTPClient", _FakeClient)

    result = await cors.run(
        "https://example.com",
        scope=_scope(),
    )

    assert result["findings"] == []
    assert result["count"] == 0
    assert len(result["candidates"]) == 1
    assert result["candidates"][0]["confidence"] == "candidate"
    assert result["candidates"][0]["requires_authenticated_resource_validation"] is True
    assert len(result["observations"]) == 1


@pytest.mark.asyncio
async def test_auth_scanner_never_attempts_default_credentials(monkeypatch):
    from talisman.modules.scanner import auth

    async def fake_login_form(url, client):
        return {
            "page_url": url,
            "action": url.rstrip("/") + "/login",
            "user_field": "username",
            "pass_field": "password",
            "csrf_field_observed": None,
        }

    monkeypatch.setattr(auth, "_detect_login_form", fake_login_form)
    monkeypatch.setattr(auth, "TalismanHTTPClient", _FakeClient)

    result = await auth.run(
        "https://example.com",
        scope=_scope(),
        test_default_creds=True,
    )

    assert result["findings"] == []
    assert result["count"] == 0
    assert result["credential_testing_enabled"] is False
    assert result["credential_testing_skipped"] is True
    assert any(
        item["type"] == "csrf_token_not_observed_in_form_markup"
        for item in result["observations"]
    )


@pytest.mark.asyncio
async def test_headers_and_cors_require_scope():
    from talisman.modules.scanner import cors, headers

    header_result = await headers.run("https://example.com")
    cors_result = await cors.run("https://example.com")

    assert header_result["error"] == "scope_enforcer_required"
    assert cors_result["error"] == "scope_enforcer_required"
