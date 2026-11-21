"""Regression tests for HTTP scope enforcement and redirect boundaries."""
from __future__ import annotations

import httpx
import pytest
import respx

from talisman.engine.scope import ScopeConfig, ScopeEnforcer, ScopeViolationError, scope_context
from talisman.utils.http_client import TalismanHTTPClient


def _scope() -> ScopeEnforcer:
    return ScopeEnforcer(ScopeConfig(include=["target.example"]))


@pytest.mark.asyncio
async def test_out_of_scope_request_is_blocked_before_network():
    with scope_context(_scope()):
        async with TalismanHTTPClient(max_retries=1) as client:
            with pytest.raises(ScopeViolationError):
                await client.get("https://outside.example/")


@pytest.mark.asyncio
@respx.mock
async def test_in_scope_request_is_allowed():
    route = respx.get("https://target.example/status").mock(
        return_value=httpx.Response(200, text="ok")
    )

    with scope_context(_scope()):
        async with TalismanHTTPClient(max_retries=1) as client:
            response = await client.get("https://target.example/status")

    assert response.status_code == 200
    assert route.called


@pytest.mark.asyncio
@respx.mock
async def test_cross_origin_redirect_is_not_followed():
    start = respx.get("https://target.example/start").mock(
        return_value=httpx.Response(
            302, headers={"Location": "https://outside.example/collect"}
        )
    )
    destination = respx.get("https://outside.example/collect").mock(
        return_value=httpx.Response(200, text="should not be requested")
    )

    with scope_context(_scope()):
        async with TalismanHTTPClient(max_retries=1) as client:
            response = await client.get("https://target.example/start")

    assert start.called
    assert response.status_code == 302
    assert not destination.called


@pytest.mark.asyncio
@respx.mock
async def test_same_origin_redirect_is_followed():
    start = respx.get("https://target.example/start").mock(
        return_value=httpx.Response(302, headers={"Location": "/final"})
    )
    final = respx.get("https://target.example/final").mock(
        return_value=httpx.Response(200, text="final")
    )

    with scope_context(_scope()):
        async with TalismanHTTPClient(max_retries=1) as client:
            response = await client.get("https://target.example/start")

    assert start.called
    assert final.called
    assert response.status_code == 200
    assert response.text == "final"


@pytest.mark.asyncio
@respx.mock
async def test_explicit_external_intelligence_request_can_opt_out():
    route = respx.get("https://intel.example/lookup").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )

    with scope_context(_scope()):
        async with TalismanHTTPClient(max_retries=1) as client:
            response = await client.get(
                "https://intel.example/lookup", scope_exempt=True
            )

    assert route.called
    assert response.status_code == 200


def test_tls_verification_is_enabled_by_default():
    assert TalismanHTTPClient().verify_ssl is True
