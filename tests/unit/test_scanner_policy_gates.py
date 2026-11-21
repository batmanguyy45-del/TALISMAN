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


@pytest.mark.asyncio
async def test_generic_prototype_nosqli_and_deserialization_scanners_are_disabled():
    from talisman.modules.scanner import deserialization, nosqli, prototype

    for module in (prototype, nosqli, deserialization):
        result = await module.run(
            target="https://example.com",
            scope=_scope(),
        )
        assert result["skipped"] is True
        assert result["findings"] == []
        assert result["count"] == 0


@pytest.mark.asyncio
async def test_cache_poisoning_requires_destructive_probe_opt_in(monkeypatch):
    from talisman.modules.scanner import cache_poison

    class MustNotStartClient:
        def __init__(self, *args, **kwargs):
            raise AssertionError("cache mutation must be blocked by default")

    monkeypatch.setattr(cache_poison, "TalismanHTTPClient", MustNotStartClient)
    result = await cache_poison.run(
        "https://example.com",
        scope=_scope(),
    )

    assert result["skipped"] is True
    assert result["findings"] == []
    assert "Destructive probe blocked" in result["reason"]


@pytest.mark.asyncio
async def test_mfa_scan_is_passive_and_sends_no_otp_submissions(monkeypatch):
    from talisman.modules.scanner import mfa_bypass

    monkeypatch.setattr(mfa_bypass, "TalismanHTTPClient", _FakeClient)
    result = await mfa_bypass.run(
        "https://example.com",
        scope=_scope(),
    )

    assert result["findings"] == []
    assert result["count"] == 0
    assert result["otp_attempts_sent"] == 0


@pytest.mark.asyncio
async def test_crlf_requires_scope_and_returns_candidates_only(monkeypatch):
    from talisman.modules.scanner import crlf

    missing_scope = await crlf.run("https://example.com")
    assert missing_scope["error"] == "scope_enforcer_required"

    monkeypatch.setattr(crlf, "TalismanHTTPClient", _FakeClient)
    result = await crlf.run(
        "https://example.com",
        scope=_scope(),
    )

    assert result["findings"] == []
    assert result["count"] == 0


@pytest.mark.asyncio
async def test_cache_deception_requires_destructive_probe_opt_in(monkeypatch):
    from talisman.modules.scanner import cache_deception

    class MustNotStartClient:
        def __init__(self, *args, **kwargs):
            raise AssertionError("cache path probes must be blocked by default")

    monkeypatch.setattr(cache_deception, "TalismanHTTPClient", MustNotStartClient)
    result = await cache_deception.run(
        "https://example.com",
        scope=_scope(),
    )

    assert result["skipped"] is True
    assert result["findings"] == []
    assert "Destructive probe blocked" in result["reason"]


@pytest.mark.asyncio
async def test_verb_tampering_tests_only_safe_methods_by_default(monkeypatch):
    from talisman.modules.scanner import verb_tampering

    seen_methods = []

    class Response:
        status_code = 404
        headers = {"allow": "GET, HEAD, OPTIONS"}
        text = ""

    class Client:
        def __init__(self, *args, **kwargs):
            assert kwargs.get("scope") is not None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def request(self, method, url, **kwargs):
            seen_methods.append(method)
            return Response()

    monkeypatch.setattr(verb_tampering, "TalismanHTTPClient", Client)
    result = await verb_tampering.run(
        "https://example.com",
        scope=_scope(),
    )

    assert result["findings"] == []
    assert result["mutating_method_probes_enabled"] is False
    assert set(seen_methods) <= {"GET", "HEAD", "OPTIONS", "TRACE"}
    assert not ({"POST", "PUT", "PATCH", "DELETE", "CONNECT"} & set(seen_methods))


@pytest.mark.asyncio
async def test_rate_limit_scanner_requires_operator_supplied_fixture():
    from talisman.modules.scanner import rate_limit

    result = await rate_limit.run(
        "https://example.com",
        scope=_scope(),
    )

    assert result["skipped"] is True
    assert result["findings"] == []
    assert "test_fixture" in result["reason"]


@pytest.mark.asyncio
async def test_rate_limit_fixture_produces_candidate_not_confirmed_finding(monkeypatch):
    from talisman.modules.scanner import rate_limit

    class Response:
        status_code = 200
        headers = {}

    class Client:
        def __init__(self, *args, **kwargs):
            assert kwargs.get("scope") is not None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, *args, **kwargs):
            return Response()

    monkeypatch.setattr(rate_limit, "TalismanHTTPClient", Client)
    writable_scope = _scope(
        allow_writes=True,
        avoid_writes=False,
        avoid_destructive=False,
    )
    result = await rate_limit.run(
        "https://example.com",
        scope=writable_scope,
        test_fixture={
            "endpoint": "/login",
            "method": "POST",
            "payload": {"username": "disposable-account", "password": "invalid"},
            "attempts": 3,
        },
    )

    assert result["findings"] == []
    assert result["candidate_count"] == 1
    assert result["candidates"][0]["confidence"] == "candidate"
    assert result["observations"][0]["attempts"] == 3


@pytest.mark.asyncio
async def test_graphql_discovery_uses_read_only_get_requests(monkeypatch):
    from talisman.modules.api import graphql

    class Client:
        methods = []

        def __init__(self, *args, **kwargs):
            assert kwargs.get("scope") is not None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, *args, **kwargs):
            self.methods.append("GET")
            return _Response()

        async def post(self, *args, **kwargs):
            raise AssertionError("GraphQL discovery must not send POST mutations")

    monkeypatch.setattr(graphql, "TalismanHTTPClient", Client)
    result = await graphql.run(
        "https://example.com",
        scope=_scope(),
    )

    assert result["findings"] == []
    assert result["count"] == 0
    assert result["state_changing_probes_sent"] == 0


@pytest.mark.asyncio
async def test_oauth_discovery_performs_no_token_or_authorization_posts(monkeypatch):
    from talisman.modules.api import oauth

    class Client:
        def __init__(self, *args, **kwargs):
            assert kwargs.get("scope") is not None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, *args, **kwargs):
            return _Response()

        async def post(self, *args, **kwargs):
            raise AssertionError("OAuth discovery must not exchange tokens")

    monkeypatch.setattr(oauth, "TalismanHTTPClient", Client)
    result = await oauth.run(
        "https://example.com",
        scope=_scope(),
        client_id="disposable-client",
    )

    assert result["findings"] == []
    assert result["active_tests_performed"] is False


@pytest.mark.asyncio
async def test_swagger_requires_scope_and_does_not_probe_mutating_endpoints(monkeypatch):
    from talisman.modules.api import swagger_audit

    missing = await swagger_audit.run("https://example.com")
    assert missing["error"] == "scope_enforcer_required"

    class Client:
        def __init__(self, *args, **kwargs):
            assert kwargs.get("scope") is not None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, *args, **kwargs):
            return _Response()

        async def request(self, *args, **kwargs):
            raise AssertionError("OpenAPI audit must not execute PUT/DELETE/PATCH probes")

    monkeypatch.setattr(swagger_audit, "TalismanHTTPClient", Client)
    result = await swagger_audit.run(
        "https://example.com",
        scope=_scope(),
        test_endpoints=True,
    )

    assert result["findings"] == []
    assert result["active_endpoint_tests_performed"] is False


@pytest.mark.asyncio
async def test_jwt_offline_weak_secret_result_never_returns_secret(monkeypatch):
    import base64
    import hashlib
    import hmac
    import json

    from talisman.modules.api import jwt

    secret = "fixture-only-secret"
    monkeypatch.setattr(jwt, "JWT_WEAK_SECRETS", [secret])

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "test-user", "role": "user"}
    encoded_header = jwt._encode_b64(header)
    encoded_payload = jwt._encode_b64(payload)
    message = f"{encoded_header}.{encoded_payload}".encode()
    signature = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), message, hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    token = f"{encoded_header}.{encoded_payload}.{signature}"

    result = await jwt.run(
        target="example.com",
        token=token,
        crack_secret=True,
    )

    assert result["findings"] == []
    assert result["count"] == 0
    assert result["candidates"][0]["type"] == "jwt_weak_hmac_secret"
    assert result["candidates"][0]["secret_value"] == "[REDACTED]"
    assert secret not in str(result)


@pytest.mark.asyncio
async def test_jwt_live_endpoint_requires_scope_and_destructive_permission():
    from talisman.modules.api import jwt

    missing = await jwt.run(
        target="example.com",
        token="eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.",
        endpoint="https://example.com/account",
    )
    assert missing["error"] == "scope_enforcer_required_for_live_jwt_tests"

    blocked = await jwt.run(
        target="example.com",
        token="eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.",
        endpoint="https://example.com/account",
        scope=_scope(),
    )
    assert blocked["skipped"] is True
    assert blocked["findings"] == []
