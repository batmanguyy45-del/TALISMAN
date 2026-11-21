"""Tests for safe scope-bound Nuclei execution."""
from __future__ import annotations

import json

import pytest

from talisman.engine.scope import ScopeConfig, ScopeEnforcer
from talisman.modules.scanner import nuclei_runner


def _active_scope(rate: float = 2.0) -> ScopeEnforcer:
    """Nuclei execution requires explicit authorization for state-changing templates."""
    return ScopeEnforcer(
        ScopeConfig(
            include=["example.com"],
            service_allowlist=[],
            max_requests_per_second=rate,
            allow_state_changing_requests=True,
            avoid_writes=False,
            avoid_destructive=False,
        )
    )


@pytest.mark.asyncio
async def test_nuclei_requires_scope_before_checking_binary(monkeypatch):
    def should_not_check_binary(*args, **kwargs):
        raise AssertionError("Nuclei binary should not be inspected without scope")

    monkeypatch.setattr(nuclei_runner.shutil, "which", should_not_check_binary)
    result = await nuclei_runner.run(target="https://example.com")
    assert result["error"] == "scope_enforcer_required"


@pytest.mark.asyncio
async def test_nuclei_receives_safe_flags_and_discards_out_of_scope_results(monkeypatch):
    monkeypatch.setenv("TALISMAN_ALLOW_UNPINNED_NUCLEI", "1")
    scope = _active_scope()
    monkeypatch.setattr(nuclei_runner.shutil, "which", lambda _: "/usr/bin/nuclei")

    class FakeStream:
        def __init__(self, data):
            self.data = data

        async def read(self, size):
            chunk, self.data = self.data[:size], self.data[size:]
            return chunk

    class FakeProcess:
        returncode = None

        def __init__(self):
            output = [
                {
                    "matched-at": "https://example.com/vulnerable",
                    "info": {"name": "Scoped candidate", "severity": "medium"},
                    "template-id": "test-template",
                },
                {
                    "matched-at": "https://outside.example.test/vulnerable",
                    "info": {"name": "Out-of-scope", "severity": "critical"},
                    "template-id": "outside-template",
                },
            ]
            self.stdout = FakeStream(
                ("\n".join(json.dumps(item) for item in output)).encode()
            )
            self.killed = False

        async def wait(self):
            self.returncode = 0
            return 0

        def kill(self):
            self.killed = True

    captured = {}

    async def fake_create_subprocess_exec(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.setattr(
        nuclei_runner.asyncio,
        "create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    result = await nuclei_runner.run(
        target="https://example.com",
        scope=scope,
    )

    args = captured["args"]
    assert "-disable-redirects" in args
    assert "-restrict-local-network-access" in args
    assert "-no-interactsh" in args
    assert "-exclude-tags" in args
    assert "dos,intrusive,fuzz,bruteforce" in args
    assert "-retries" in args and "0" in args
    assert "-rate-limit" in args and "2" in args
    assert "-concurrency" in args and "4" in args
    assert result["count"] == 1
    assert result["out_of_scope_results_discarded"] == 1


@pytest.mark.asyncio
async def test_nuclei_out_of_scope_target_is_blocked_before_process_launch(monkeypatch):
    def should_not_launch(*args, **kwargs):
        raise AssertionError("Nuclei must not run for out-of-scope target")

    monkeypatch.setattr(nuclei_runner.shutil, "which", lambda _: "/usr/bin/nuclei")
    monkeypatch.setattr(
        nuclei_runner.asyncio,
        "create_subprocess_exec",
        should_not_launch,
    )
    scope = ScopeEnforcer(
        ScopeConfig(include=["example.com"], service_allowlist=[])
    )
    result = await nuclei_runner.run(
        target="https://outside.example.test",
        scope=scope,
    )
    assert result["error"]


@pytest.mark.asyncio
async def test_nuclei_output_is_bounded_and_process_is_killed_on_limit(monkeypatch):
    monkeypatch.setenv("TALISMAN_ALLOW_UNPINNED_NUCLEI", "1")
    scope = _active_scope()
    monkeypatch.setattr(nuclei_runner.shutil, "which", lambda _: "/usr/bin/nuclei")
    monkeypatch.setattr(nuclei_runner, "MAX_NUCLEI_OUTPUT_BYTES", 32)

    class FakeStream:
        def __init__(self, data):
            self.data = data

        async def read(self, size):
            chunk, self.data = self.data[:size], self.data[size:]
            return chunk

    class FakeProcess:
        def __init__(self):
            self.returncode = None
            self.stdout = FakeStream(b"x" * 128)
            self.killed = False

        def kill(self):
            self.killed = True
            self.returncode = -9

        async def wait(self):
            if self.returncode is None:
                self.returncode = -9
            return self.returncode

    process = FakeProcess()

    async def fake_create_subprocess_exec(*args, **kwargs):
        return process

    monkeypatch.setattr(
        nuclei_runner.asyncio,
        "create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    result = await nuclei_runner.run(
        target="https://example.com",
        scope=scope,
    )

    assert result["error"] == "output_limit"
    assert result["findings"] == []
    assert process.killed is True


@pytest.mark.asyncio
async def test_nuclei_skips_when_configured_rate_is_below_its_minimum(monkeypatch):
    monkeypatch.setenv("TALISMAN_ALLOW_UNPINNED_NUCLEI", "1")
    scope = ScopeEnforcer(
        ScopeConfig(
            include=["example.com"],
            service_allowlist=[],
            max_requests_per_second=0.5,
            allow_state_changing_requests=True,
            avoid_writes=False,
            avoid_destructive=False,
        )
    )

    def should_not_lookup_binary(*args, **kwargs):
        raise AssertionError("Nuclei cannot honor a sub-1 request/second limit")

    monkeypatch.setattr(nuclei_runner.shutil, "which", should_not_lookup_binary)
    result = await nuclei_runner.run(
        target="https://example.com",
        scope=scope,
    )

    assert result["skipped"] is True
    assert "below 1 request/second" in result["reason"]



@pytest.mark.asyncio
async def test_nuclei_requires_explicit_destructive_permission_before_binary_lookup(monkeypatch):
    monkeypatch.setenv("TALISMAN_ALLOW_UNPINNED_NUCLEI", "1")
    scope = ScopeEnforcer(
        ScopeConfig(include=["example.com"], service_allowlist=[])
    )

    def should_not_lookup_binary(*args, **kwargs):
        raise AssertionError("Nuclei must not be inspected or launched without destructive permission")

    monkeypatch.setattr(nuclei_runner.shutil, "which", should_not_lookup_binary)
    result = await nuclei_runner.run(
        target="https://example.com",
        scope=scope,
    )

    assert result["skipped"] is True
    assert result["findings"] == []
    assert "Explicit destructive-scope permission is required" in result["reason"]



@pytest.mark.asyncio
async def test_nuclei_requires_unpinned_dns_acknowledgement_before_binary_lookup(monkeypatch):
    monkeypatch.delenv("TALISMAN_ALLOW_UNPINNED_NUCLEI", raising=False)
    scope = _active_scope()

    def should_not_lookup_binary(*args, **kwargs):
        raise AssertionError("Nuclei binary must not be inspected without unpinned DNS acknowledgement")

    monkeypatch.setattr(nuclei_runner.shutil, "which", should_not_lookup_binary)
    result = await nuclei_runner.run(
        target="https://example.com",
        scope=scope,
    )

    assert result["skipped"] is True
    assert result["findings"] == []
    assert "TALISMAN_ALLOW_UNPINNED_NUCLEI=1" in result["reason"]
