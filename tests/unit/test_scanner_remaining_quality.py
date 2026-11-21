"""Regression coverage for scanners missed by the first quality pass."""
from __future__ import annotations

import pytest

from talisman.engine.scope import ScopeConfig, ScopeEnforcer


def _scope(*, allow_posts: bool = False):
    return ScopeEnforcer(
        ScopeConfig(
            include=["example.com"],
            service_allowlist=[],
            allow_state_changing_requests=allow_posts,
            avoid_writes=not allow_posts,
            avoid_destructive=not allow_posts,
        )
    )


class _FakeClient:
    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


class _FakeSession:
    def __init__(self):
        self.saved = []

    async def add_finding(self, *args, **kwargs):
        self.saved.append((args, kwargs))


@pytest.mark.asyncio
async def test_remaining_scanners_require_explicit_scope():
    from talisman.modules.scanner import (
        dangling_markup,
        dom_clobbering,
        git_exposure,
        hpp,
        ldap_injection,
        ssji,
        unicode_attacks,
    )

    for module in (
        dangling_markup,
        dom_clobbering,
        git_exposure,
        hpp,
        ldap_injection,
        ssji,
        unicode_attacks,
    ):
        result = await module.run("https://example.com")
        assert result["error"] == "scope_enforcer_required"
        assert result["findings"] == []


@pytest.mark.asyncio
async def test_dangling_markup_reflection_is_candidate_not_confirmed_finding(monkeypatch):
    from talisman.modules.scanner import dangling_markup

    async def reflected(*args, **kwargs):
        return [{
            "type": "dangling_markup",
            "endpoint": "/search",
            "canary": "TLSM-CANARY",
            "evidence": "Canary followed by reflected markup",
        }]

    async def form_reflected(*args, **kwargs):
        return [{
            "type": "form_hijack",
            "endpoint": "/login",
            "evidence": "A form-like canary appeared in the response",
        }]

    monkeypatch.setattr(dangling_markup, "TalismanHTTPClient", _FakeClient)
    monkeypatch.setattr(dangling_markup, "_test_dangling_markup", reflected)
    monkeypatch.setattr(dangling_markup, "_test_dangling_form_hijack", form_reflected)
    monkeypatch.setattr(dangling_markup, "DANGLING_ENDPOINTS", ["/search"])
    session = _FakeSession()

    result = await dangling_markup.run(
        "https://example.com",
        scope=_scope(),
        session=session,
    )

    assert result["findings"] == []
    assert result["count"] == 0
    assert result["candidate_count"] == 2
    assert all(item["requires_browser_verification"] for item in result["candidates"])
    assert session.saved == []


@pytest.mark.asyncio
async def test_dom_clobbering_requires_browser_gadget_proof_and_gates_posts(monkeypatch):
    from talisman.modules.scanner import dom_clobbering

    calls = []

    async def reflected(url, endpoint, client, allow_post_probes=False):
        calls.append(allow_post_probes)
        return [{
            "type": "generic_html_clobbering",
            "endpoint": endpoint,
            "canary_id": "TLSM-CANARY",
            "evidence": "The canary was reflected",
        }]

    async def sink(url, endpoint, client, allow_post_probes=False):
        calls.append(allow_post_probes)
        return []

    monkeypatch.setattr(dom_clobbering, "TalismanHTTPClient", _FakeClient)
    monkeypatch.setattr(dom_clobbering, "_test_dom_clobbering", reflected)
    monkeypatch.setattr(dom_clobbering, "_test_dom_clobbering_sinks", sink)
    monkeypatch.setattr(dom_clobbering, "HTML_INJECTION_ENDPOINTS", ["/search"])
    session = _FakeSession()

    result = await dom_clobbering.run(
        "https://example.com",
        scope=_scope(),
        session=session,
    )

    assert result["findings"] == []
    assert result["count"] == 0
    assert result["candidate_count"] == 1
    assert result["candidates"][0]["requires_browser_verification"] is True
    assert calls and not any(calls)
    assert result["post_probes_enabled"] is False
    assert session.saved == []


@pytest.mark.asyncio
async def test_git_file_existence_is_candidate_and_evidence_is_redacted(monkeypatch):
    from talisman.modules.scanner import git_exposure

    async def exposed(*args, **kwargs):
        return {
            "path": "/.env",
            "status": 200,
            "size": 32,
            "type": "env_exposure",
            "sensitive": True,
            "evidence": "API_KEY=ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        }

    monkeypatch.setattr(git_exposure, "TalismanHTTPClient", _FakeClient)
    monkeypatch.setattr(git_exposure, "_test_path", exposed)
    monkeypatch.setattr(git_exposure, "EXPOSURE_PATHS", ["/.env"])
    session = _FakeSession()

    result = await git_exposure.run(
        "https://example.com",
        scope=_scope(),
        session=session,
    )

    assert result["findings"] == []
    assert result["count"] == 0
    assert result["candidate_count"] == 1
    assert result["candidates"][0]["requires_manual_validation"] is True
    assert "ghp_abcdefghijklmnopqrstuvwxyz" not in result["candidates"][0]["evidence"]
    assert session.saved == []


@pytest.mark.asyncio
async def test_hpp_reflection_is_candidate_and_mutations_are_gated(monkeypatch):
    from talisman.modules.scanner import hpp

    async def query_candidate(*args, **kwargs):
        return [{
            "type": "query_hpp",
            "endpoint": "/search",
            "parameter": "role",
            "canary": "TLSMHPP-CANARY",
            "evidence": "Canary reflected",
        }]

    async def should_not_post(*args, **kwargs):
        raise AssertionError("POST HPP probe must be skipped without opt-in")

    monkeypatch.setattr(hpp, "TalismanHTTPClient", _FakeClient)
    monkeypatch.setattr(hpp, "_test_query_hpp", query_candidate)
    monkeypatch.setattr(hpp, "_test_body_hpp", should_not_post)
    monkeypatch.setattr(hpp, "_test_mixed_param_sources", should_not_post)
    monkeypatch.setattr(hpp, "HPP_ENDPOINTS", ["/search"])
    session = _FakeSession()

    result = await hpp.run(
        "https://example.com",
        scope=_scope(),
        session=session,
    )

    assert result["findings"] == []
    assert result["count"] == 0
    assert result["candidate_count"] == 1
    assert result["candidates"][0]["requires_semantic_verification"] is True
    assert result["post_probes_enabled"] is False
    assert any("Duplicate-header HPP is not attempted" in item for item in result["skipped_vectors"])
    assert session.saved == []


@pytest.mark.asyncio
async def test_ldap_probes_are_skipped_without_destructive_permission(monkeypatch):
    from talisman.modules.scanner import ldap_injection

    class MustNotStartClient:
        def __init__(self, *args, **kwargs):
            raise AssertionError("LDAP POST probes must not start by default")

    monkeypatch.setattr(ldap_injection, "TalismanHTTPClient", MustNotStartClient)

    result = await ldap_injection.run(
        "https://example.com",
        scope=_scope(),
    )

    assert result["skipped"] is True
    assert result["findings"] == []
    assert result["candidates"] == []
    assert "POST blocked" in result["reason"]


@pytest.mark.asyncio
async def test_ssji_generic_command_and_timing_probes_are_disabled(monkeypatch):
    from talisman.modules.scanner import ssji

    class MustNotStartClient:
        def __init__(self, *args, **kwargs):
            raise AssertionError("Unsafe generic SSJI probes must not run")

    monkeypatch.setattr(ssji, "TalismanHTTPClient", MustNotStartClient)

    result = await ssji.run(
        "https://example.com",
        scope=_scope(),
    )

    assert result["skipped"] is True
    assert result["findings"] == []
    assert result["candidates"] == []
    assert "No network requests were sent" in result["reason"]


@pytest.mark.asyncio
async def test_unicode_post_probes_are_gated_and_passive_content_is_observation(monkeypatch):
    from talisman.modules.scanner import unicode_attacks

    async def response_observation(*args, **kwargs):
        return [{
            "type": "bidi_in_response",
            "endpoint": "/api/user",
            "chars_found": ["RIGHT-TO-LEFT OVERRIDE (U+202E) x1"],
            "evidence": "Response contains a bidi control character",
        }]

    async def should_not_post(*args, **kwargs):
        raise AssertionError("Unicode POST probes must be skipped without opt-in")

    monkeypatch.setattr(unicode_attacks, "TalismanHTTPClient", _FakeClient)
    monkeypatch.setattr(unicode_attacks, "_test_response_unicode", response_observation)
    monkeypatch.setattr(unicode_attacks, "_test_bidi_reflection", should_not_post)
    monkeypatch.setattr(unicode_attacks, "_test_normalization_bypass", should_not_post)
    monkeypatch.setattr(unicode_attacks, "_test_homoglyph_bypass", should_not_post)
    monkeypatch.setattr(unicode_attacks, "UNICODE_ENDPOINTS", ["/api/user"])
    session = _FakeSession()

    result = await unicode_attacks.run(
        "https://example.com",
        scope=_scope(),
        session=session,
    )

    assert result["findings"] == []
    assert result["count"] == 0
    assert result["observation_count"] == 1
    assert result["observations"][0]["classification"] == "security_posture_observation"
    assert result["post_probes_enabled"] is False
    assert session.saved == []
