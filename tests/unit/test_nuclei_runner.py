"""Tests for safe scope-bound Nuclei execution."""
from __future__ import annotations

import json

import pytest

from talisman.engine.scope import ScopeConfig, ScopeEnforcer
from talisman.modules.scanner import nuclei_runner


@pytest.mark.asyncio
async def test_nuclei_requires_scope_before_checking_binary(monkeypatch):
    def should_not_check_binary(*args, **kwargs):
        raise AssertionError("Nuclei binary should not be inspected without scope")

    monkeypatch.setattr(nuclei_runner.shutil, "which", should_not_check_binary)
    result = await nuclei_runner.run(target="https://example.com")
    assert result["error"] == "scope_enforcer_required"


@pytest.mark.asyncio
async def test_nuclei_receives_safe_flags_and_discards_out_of_scope_results(monkeypatch):
    scope = ScopeEnforcer(
        ScopeConfig(include=["example.com"], service_allowlist=[])
    )
    monkeypatch.setattr(nuclei_runner.shutil, "which", lambda _: "/usr/bin/nuclei")

    class FakeProcess:
        returncode = 0

        async def communicate(self):
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
            return ("\n".join(json.dumps(item) for item in output).encode(), b"")

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
