"""Regression tests for safe OAST callback validation."""
from __future__ import annotations

import ipaddress

import pytest

from talisman.engine.scope import ScopeEnforcer, ScopeViolationError
from talisman.utils.oast import (
    OASTClient,
    normalize_oast_domain,
    validate_public_oast_domain,
)


@pytest.mark.parametrize(
    "value",
    [
        "oast.pro",
        "https://callback.oast.pro/",
        "my-callback.example.net",
    ],
)
def test_public_hostname_oast_values_are_normalized(value):
    host = normalize_oast_domain(value)
    assert host == "callback.oast.pro" if value.startswith("https://") else host == value


@pytest.mark.parametrize(
    "value",
    [
        "localhost",
        "http://127.0.0.1/",
        "http://169.254.169.254/",
        "metadata.google.internal",
        "callback.oast.pro/path",
        "callback.oast.pro:8443",
        "callback.oast.pro?next=localhost",
        "callback.oast.pro@127.0.0.1",
        "file:///etc/passwd",
    ],
)
def test_local_private_and_non_hostname_oast_values_are_rejected(value):
    with pytest.raises(ValueError):
        normalize_oast_domain(value)


def test_oast_client_validates_custom_server():
    with pytest.raises(ValueError):
        OASTClient(custom_url="http://127.0.0.1/")


@pytest.mark.asyncio
async def test_public_oast_hostname_is_checked_against_resolved_addresses(monkeypatch):
    async def resolve_public(self, target, method="GET"):
        return (ipaddress.ip_address("93.184.216.34"),)

    monkeypatch.setattr(
        ScopeEnforcer,
        "resolve_network_destination",
        resolve_public,
    )
    assert await validate_public_oast_domain("callback.oast.pro") == "callback.oast.pro"


@pytest.mark.asyncio
async def test_oast_hostname_resolving_to_private_ip_is_rejected(monkeypatch):
    async def resolve_private(self, target, method="GET"):
        raise ScopeViolationError("non-public address")

    monkeypatch.setattr(
        ScopeEnforcer,
        "resolve_network_destination",
        resolve_private,
    )
    with pytest.raises(ScopeViolationError, match="non-public address"):
        await validate_public_oast_domain("callback.oast.pro")
