"""Regression tests for candidate-vs-confirmed scanner output quality."""
from __future__ import annotations

import pytest

from talisman.engine.scope import ScopeConfig, ScopeEnforcer
from talisman.modules.scanner import (
    csp_evaluator,
    dep_confusion,
    file_upload_scanner,
    idor,
    mass_assignment,
    parser_differential,
    second_order,
    sqli,
    ssrf,
    xss,
)


class _FakeClient:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


class _NoFindingSession:
    def __init__(self):
        self.added = []

    async def add_finding(self, *args, **kwargs):
        self.added.append((args, kwargs))


def _scope(*, writes=False, destructive=False, internal_ssrf=False):
    return ScopeEnforcer(
        ScopeConfig(
            include=["example.com"],
            service_allowlist=[],
            allow_state_changing_requests=writes,
            avoid_writes=not writes,
            avoid_destructive=not destructive,
            allow_internal_ssrf_probes=internal_ssrf,
        )
    )


@pytest.mark.asyncio
async def test_xss_reflection_is_candidate_not_confirmed_finding(monkeypatch):
    async def candidate(*args, **kwargs):
        return {
            "param": "q",
            "payload": "<script>canary()</script>",
            "context": "html",
            "method": "GET",
            "marker": "canary",
            "evidence": "Unencoded response reflection",
        }

    monkeypatch.setattr(xss, "_test_param", candidate)
    monkeypatch.setattr(xss, "TalismanHTTPClient", _FakeClient)
    session = _NoFindingSession()

    result = await xss.run(
        target="https://example.com/?q=test",
        scope=_scope(),
        session=session,
    )

    assert result["findings"] == []
    assert result["count"] == 0
    assert result["candidate_count"] == 1
    assert result["candidates"][0]["requires_browser_verification"] is True
    assert session.added == []


@pytest.mark.asyncio
async def test_sqli_error_signature_is_candidate_until_query_execution_verified(monkeypatch):
    async def candidate(*args, **kwargs):
        return {
            "technique": "error_based",
            "dbms": "MySQL",
            "payload": "'",
            "evidence": "You have an error in your SQL syntax",
        }

    monkeypatch.setattr(sqli, "_test_error_based", candidate)
    monkeypatch.setattr(sqli, "TalismanHTTPClient", _FakeClient)
    session = _NoFindingSession()

    result = await sqli.run(
        target="https://example.com/?id=1",
        scope=_scope(),
        session=session,
        techniques=["error"],
    )

    assert result["findings"] == []
    assert result["count"] == 0
    assert result["candidate_count"] == 1
    assert result["candidates"][0]["requires_manual_verification"] is True
    assert session.added == []


def test_ssrf_internal_and_non_http_targets_are_classified_as_internal():
    assert ssrf._is_internal_ssrf_target(
        "http://169.254.169.254/latest/meta-data/"
    )
    assert ssrf._is_internal_ssrf_target("http://127.0.0.1/")
    assert ssrf._is_internal_ssrf_target("http://metadata.google.internal/")
    assert ssrf._is_internal_ssrf_target("file:///etc/passwd")
    assert ssrf._is_internal_ssrf_target("gopher://127.0.0.1:6379/_INFO")
    assert not ssrf._is_internal_ssrf_target("https://public.example/")


@pytest.mark.asyncio
async def test_ssrf_internal_probes_are_disabled_by_default(monkeypatch):
    seen = []

    async def record_probe(url, param, client, oast_domain, allow_internal_probes=False):
        seen.append(allow_internal_probes)
        return None

    monkeypatch.setattr(ssrf, "_test_ssrf_param", record_probe)
    monkeypatch.setattr(ssrf, "TalismanHTTPClient", _FakeClient)

    result = await ssrf.run(
        target="https://example.com/?url=",
        scope=_scope(internal_ssrf=False),
    )

    assert seen
    assert all(value is False for value in seen)
    assert result["findings"] == []
    assert result["internal_probes_enabled"] is False


@pytest.mark.asyncio
async def test_ssrf_internal_probes_require_explicit_scope_opt_in(monkeypatch):
    seen = []

    async def record_probe(url, param, client, oast_domain, allow_internal_probes=False):
        seen.append(allow_internal_probes)
        return None

    monkeypatch.setattr(ssrf, "_test_ssrf_param", record_probe)
    monkeypatch.setattr(ssrf, "TalismanHTTPClient", _FakeClient)

    result = await ssrf.run(
        target="https://example.com/?url=",
        scope=_scope(internal_ssrf=True),
    )

    assert seen
    assert all(value is True for value in seen)
    assert result["internal_probes_enabled"] is True


@pytest.mark.asyncio
async def test_upload_acceptance_is_candidate_until_persistence_and_execution_verified(monkeypatch):
    async def upload(*args, **kwargs):
        return [{"issue": "script_upload_accepted", "filename": "test.php"}]

    async def content_type(*args, **kwargs):
        return [{"issue": "content_type_bypass", "filename": "test.php"}]

    async def extension(*args, **kwargs):
        return []

    async def magic(*args, **kwargs):
        return []

    monkeypatch.setattr(file_upload_scanner, "_test_upload_endpoint", upload)
    monkeypatch.setattr(file_upload_scanner, "_test_content_type_bypass", content_type)
    monkeypatch.setattr(file_upload_scanner, "_test_double_extension", extension)
    monkeypatch.setattr(file_upload_scanner, "_test_content_validation", magic)
    monkeypatch.setattr(file_upload_scanner, "TalismanHTTPClient", _FakeClient)
    session = _NoFindingSession()

    result = await file_upload_scanner.run(
        target="https://example.com",
        scope=_scope(writes=True, destructive=True),
        session=session,
    )

    assert result["findings"] == []
    assert result["count"] == 0
    assert result["candidate_count"] == 2
    assert session.added == []


@pytest.mark.asyncio
async def test_mass_assignment_is_candidate_until_security_impact_verified(monkeypatch):
    async def persisted_field(*args, **kwargs):
        return [{
            "field": "role",
            "injected_value": "admin",
            "confirmed_value": "admin",
            "severity": "critical",
        }]

    monkeypatch.setattr(mass_assignment, "_test_mass_assignment", persisted_field)
    monkeypatch.setattr(mass_assignment, "TalismanHTTPClient", _FakeClient)
    session = _NoFindingSession()

    result = await mass_assignment.run(
        target="https://example.com",
        scope=_scope(writes=True, destructive=True),
        session=session,
    )

    assert result["findings"] == []
    assert result["count"] == 0
    assert result["candidate_count"] == 1
    assert result["candidates"][0]["requires_impact_verification"] is True
    assert session.added == []



@pytest.mark.asyncio
async def test_sqli_time_based_probes_are_not_enabled_by_default(monkeypatch):
    time_called = False

    async def no_error(*args, **kwargs):
        return None

    async def baseline(*args, **kwargs):
        return (0.1, 0.01, 200, 1000)

    async def no_boolean(*args, **kwargs):
        return None

    async def time_probe(*args, **kwargs):
        nonlocal time_called
        time_called = True
        return None

    monkeypatch.setattr(sqli, "_test_error_based", no_error)
    monkeypatch.setattr(sqli, "_get_baseline_stats", baseline)
    monkeypatch.setattr(sqli, "_test_boolean_blind", no_boolean)
    monkeypatch.setattr(sqli, "_test_time_based", time_probe)
    monkeypatch.setattr(sqli, "TalismanHTTPClient", _FakeClient)

    result = await sqli.run(
        target="https://example.com/?id=1",
        scope=_scope(),
    )

    assert result["skipped_techniques"] == []
    assert time_called is False


@pytest.mark.asyncio
async def test_sqli_time_based_requires_destructive_opt_in():
    result = await sqli.run(
        target="https://example.com/?id=1",
        scope=_scope(),
        techniques=["time"],
    )

    assert result["skipped"] is True
    assert result["skipped_techniques"] == ["time"]
    assert result["findings"] == []


@pytest.mark.asyncio
async def test_sqli_time_based_runs_only_after_destructive_opt_in(monkeypatch):
    async def baseline(*args, **kwargs):
        return (0.1, 0.01, 200, 1000)

    async def time_candidate(*args, **kwargs):
        return {
            "technique": "time_based",
            "elapsed": 6.2,
            "baseline": 0.1,
            "evidence": "One delayed response",
        }

    monkeypatch.setattr(sqli, "_get_baseline_stats", baseline)
    monkeypatch.setattr(sqli, "_test_time_based", time_candidate)
    monkeypatch.setattr(sqli, "TalismanHTTPClient", _FakeClient)

    result = await sqli.run(
        target="https://example.com/?id=1",
        scope=_scope(writes=True, destructive=True),
        techniques=["time"],
    )

    assert result["candidate_count"] == 1
    assert result["findings"] == []
    assert result["candidates"][0]["requires_manual_verification"] is True


def test_idor_requires_classifiable_response_structure():
    assert not idor._structures_match(
        "plain response with different data",
        "another plain response with different data",
    )
    assert not idor._structures_match(
        "<html><body>one value</body></html>",
        "<html><body>another value</body></html>",
    )


@pytest.mark.asyncio
async def test_generic_second_order_mutation_scanner_is_disabled():
    result = await second_order.run(
        target="https://example.com",
        scope=_scope(),
    )

    assert result["skipped"] is True
    assert result["findings"] == []
    assert result["candidates"] == []
    assert result["count"] == 0
    assert "disposable" in result["reason"]


@pytest.mark.asyncio
async def test_generic_parser_mutation_scanner_is_disabled():
    result = await parser_differential.run(
        target="https://example.com",
        scope=_scope(),
    )

    assert result["skipped"] is True
    assert result["findings"] == []
    assert result["candidates"] == []
    assert result["count"] == 0
    assert "disposable" in result["reason"]


@pytest.mark.asyncio
async def test_disabled_mutation_scanners_still_enforce_scope():
    for module in (second_order, parser_differential):
        result = await module.run(
            target="https://outside.example",
            scope=_scope(),
        )
        assert result["error"] == "Target 'https://outside.example' is out of scope"
        assert result["findings"] == []


@pytest.mark.asyncio
async def test_csp_posture_is_observation_not_confirmed_vulnerability(monkeypatch):
    class _CSPResponse:
        headers = {}

    class _CSPClient:
        def __init__(self, *args, **kwargs):
            assert kwargs.get("scope") is not None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, *args, **kwargs):
            return _CSPResponse()

    monkeypatch.setattr(csp_evaluator, "TalismanHTTPClient", _CSPClient)
    session = _NoFindingSession()

    result = await csp_evaluator.run(
        target="https://example.com",
        scope=_scope(),
        session=session,
    )

    assert result["findings"] == []
    assert result["count"] == 0
    assert result["observation_count"] == 1
    assert result["observations"][0]["classification"] == "security_posture_observation"
    assert session.added == []


@pytest.mark.asyncio
async def test_csp_evaluator_requires_explicit_scope():
    result = await csp_evaluator.run(target="https://example.com")

    assert result["error"] == "scope_enforcer_required"
    assert result["findings"] == []


@pytest.mark.asyncio
async def test_dependency_confusion_heuristics_are_candidates_not_findings(monkeypatch):
    async def fake_fetch_package_file(url, path, client):
        if path != "/package.json":
            return None
        return {
            "path": path,
            "pm_type": "npm",
            "content": '{"dependencies":{"internal-widget":"1.2.3"}}',
            "size": 50,
        }

    async def public_registry_exists(package_name, scope):
        return package_name == "internal-widget"

    monkeypatch.setattr(dep_confusion, "_fetch_package_file", fake_fetch_package_file)
    monkeypatch.setattr(dep_confusion, "_check_npm_registry", public_registry_exists)
    monkeypatch.setattr(dep_confusion, "TalismanHTTPClient", _FakeClient)
    session = _NoFindingSession()

    result = await dep_confusion.run(
        target="https://example.com",
        scope=_scope(),
        session=session,
    )

    assert result["findings"] == []
    assert result["count"] == 0
    assert result["candidate_count"] == 1
    candidate = result["candidates"][0]
    assert candidate["package"] == "internal-widget"
    assert candidate["confidence"] == "candidate"
    assert "Confirm the package name is reserved" in candidate["requires_verification"][0]
    assert session.added == []


@pytest.mark.asyncio
async def test_csp_report_only_policy_is_not_treated_as_enforced(monkeypatch):
    class _CSPResponse:
        headers = {
            "Content-Security-Policy-Report-Only": "default-src 'self'",
        }

    class _CSPClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, *args, **kwargs):
            return _CSPResponse()

    monkeypatch.setattr(csp_evaluator, "TalismanHTTPClient", _CSPClient)
    result = await csp_evaluator.run(
        target="https://example.com",
        scope=_scope(),
    )

    assert result["csp_found"] is False
    assert result["csp"] == ""
    assert result["csp_report_only"] == "default-src 'self'"
    assert result["findings"] == []
    assert result["observations"][0]["issue"] == "no_enforced_csp"
    assert result["observations"][1]["issue"] == "report_only_policy_present"
