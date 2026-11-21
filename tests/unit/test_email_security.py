"""Regression tests for scoped email-DNS posture checks."""
from __future__ import annotations

import pytest

from talisman.engine.scope import ScopeConfig, ScopeEnforcer
from talisman.modules.network import email_security


@pytest.mark.asyncio
async def test_email_posture_requires_target_scope():
    scope = ScopeEnforcer(
        ScopeConfig(include=["example.com"], service_allowlist=[])
    )
    result = await email_security.run(
        target="https://outside.example.test",
        scope=scope,
    )
    assert result["error"]
    assert result["findings"] if "findings" in result else True


@pytest.mark.asyncio
async def test_email_posture_does_not_guess_dkim_selectors_or_create_bounty_findings(monkeypatch):
    async def fake_spf(domain, scope):
        return {"present": True, "strict": True, "issues": [], "record": "v=spf1 -all"}

    async def fake_dmarc(domain, scope):
        return {"present": True, "strict": True, "policy": "reject", "issues": []}

    monkeypatch.setattr(email_security, "_check_spf", fake_spf)
    monkeypatch.setattr(email_security, "_check_dmarc", fake_dmarc)

    scope = ScopeEnforcer(
        ScopeConfig(include=["example.com"], service_allowlist=[])
    )
    result = await email_security.run(
        target="https://example.com",
        scope=scope,
    )

    assert result["dkim"] == []
    assert result["dkim_selector_check_performed"] is False
    assert result["findings"] == []
    assert result["count"] == 0
