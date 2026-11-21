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



def test_registered_oast_token_is_required_for_payload_generation():
    client = OASTClient()
    with pytest.raises(ValueError, match="not registered"):
        client.get_xxe_payloads("guessable-token.oast.pro")


def test_registered_token_can_generate_oob_payloads_and_poll_name():
    client = OASTClient()
    full_domain = client.register()
    payloads = client.get_xxe_payloads(full_domain)
    assert payloads
    assert full_domain in payloads[0]
    assert client._registered_domain(full_domain) == full_domain


def test_payload_url_prefix_is_validated_and_token_is_retained():
    client = OASTClient()
    with pytest.raises(ValueError):
        client.get_payload_url("../bad")

    url = client.get_payload_url(prefix="research")
    host = url.removeprefix("http://").rstrip("/")
    assert client._registered_domain(host) == host
