"""Safety regression tests for high-impact AD entry points."""
from __future__ import annotations

import pytest

from talisman.engine.scope import ScopeConfig, ScopeEnforcer


def _scope():
    return ScopeEnforcer(
        ScopeConfig(include=["dc.example.com"], service_allowlist=[])
    )


@pytest.mark.asyncio
async def test_password_spray_is_disabled_without_accessing_credentials():
    from talisman.modules.activedirectory import password_spray

    result = await password_spray.run(
        "dc.example.com",
        scope=_scope(),
        users_file="/does/not/exist",
        passwords="HighlySensitive-Test-Password",
        domain="example.com",
        dc_ip="dc.example.com",
    )

    assert result["skipped"] is True
    assert result["findings"] == []
    assert result["hits"] == []
    assert "HighlySensitive-Test-Password" not in repr(result)
    assert "No usernames or passwords were read" in result["reason"]


@pytest.mark.asyncio
async def test_adcs_is_disabled_and_does_not_echo_credentials():
    from talisman.modules.activedirectory import ad_cs

    result = await ad_cs.run(
        "dc.example.com",
        scope=_scope(),
        username="operator",
        password="HighlySensitive-Test-Password",
        domain="example.com",
        dc_ip="dc.example.com",
    )

    assert result["skipped"] is True
    assert result["findings"] == []
    assert "HighlySensitive-Test-Password" not in repr(result)
    assert "No network requests were sent" in result["reason"]


@pytest.mark.asyncio
async def test_ad_sensitive_modules_fail_closed_without_scope():
    from talisman.modules.activedirectory import ad_cs, password_spray

    password_result = await password_spray.run(
        "dc.example.com",
        passwords="HighlySensitive-Test-Password",
    )
    adcs_result = await ad_cs.run(
        "dc.example.com",
        password="HighlySensitive-Test-Password",
    )

    assert password_result["error"] == "scope_enforcer_required"
    assert adcs_result["error"] == "scope_enforcer_required"
    assert "HighlySensitive-Test-Password" not in repr(password_result)
    assert "HighlySensitive-Test-Password" not in repr(adcs_result)
