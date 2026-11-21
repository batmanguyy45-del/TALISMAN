"""Regression tests for DNS reconnaissance scope controls."""
from __future__ import annotations

import inspect

import pytest

from talisman.engine.scope import ScopeConfig, ScopeEnforcer
from talisman.modules.recon import dns


@pytest.mark.asyncio
async def test_dns_scan_rejects_out_of_scope_target_before_resolving(monkeypatch):
    def resolver_must_not_be_created(*args, **kwargs):
        raise AssertionError("resolver created for an out-of-scope target")

    monkeypatch.setattr(dns.aiodns, "DNSResolver", resolver_must_not_be_created)
    scope = ScopeEnforcer(
        ScopeConfig(include=["example.com"], service_allowlist=[])
    )

    result = await dns.run(
        target="outside.example.test",
        scope=scope,
    )

    assert result["error"]


def test_dns_zone_transfer_is_not_enabled_by_default():
    parameter = inspect.signature(dns.run).parameters["zone_transfer"]
    assert parameter.default is False
