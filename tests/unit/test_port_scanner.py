"""Tests for bounded and explicit TCP port selection."""
import pytest

from talisman.modules.recon.port_scanner import (
    COMMON_PORTS,
    MAX_PORTS_PER_RUN,
    _parse_ports,
)


def test_common_ports_returns_curated_common_set():
    assert _parse_ports("common") == COMMON_PORTS


@pytest.mark.parametrize("preset", ["top-100", "top-1000", "all", ""])
def test_unsupported_port_presets_are_rejected(preset):
    with pytest.raises(ValueError):
        _parse_ports(preset)


def test_port_range_is_validated_and_bounded():
    assert _parse_ports("80-82") == [80, 81, 82]
    with pytest.raises(ValueError):
        _parse_ports("1-65535")


def test_individual_ports_are_deduplicated_and_validated():
    assert _parse_ports("443,80,443") == [80, 443]
    with pytest.raises(ValueError):
        _parse_ports("0,80")
    with pytest.raises(ValueError):
        _parse_ports("65536")


@pytest.mark.asyncio
async def test_port_scanner_refuses_to_bypass_configured_proxy():
    from talisman.engine.scope import ScopeConfig, ScopeEnforcer
    from talisman.modules.recon import port_scanner

    scope = ScopeEnforcer(
        ScopeConfig(include=["example.com"], service_allowlist=[])
    )
    result = await port_scanner.run(
        target="https://example.com",
        scope=scope,
        proxy="http://127.0.0.1:8080",
    )

    assert result["skipped"] is True
    assert result["open_ports"] == []
    assert "cannot honor the configured HTTP proxy" in result["reason"]


@pytest.mark.asyncio
async def test_port_scanner_respects_assessment_wide_concurrency(monkeypatch):
    import asyncio
    import ipaddress

    from talisman.engine.scope import ScopeConfig, ScopeEnforcer
    from talisman.modules.recon import port_scanner

    scope = ScopeEnforcer(
        ScopeConfig(
            include=["example.com"],
            service_allowlist=[],
            max_requests_per_second=20,
            max_concurrent_requests=1,
        )
    )

    async def fake_resolve(url, method="GET"):
        return (ipaddress.ip_address("93.184.216.34"),)

    active = 0
    peak_active = 0

    async def fake_connect(host, port, timeout=2.0):
        nonlocal active, peak_active
        active += 1
        peak_active = max(peak_active, active)
        await asyncio.sleep(0.12)
        active -= 1
        return port, "open"

    scope.resolve_network_destination = fake_resolve
    monkeypatch.setattr(port_scanner, "_tcp_connect", fake_connect)

    result = await port_scanner.run(
        target="https://example.com",
        scope=scope,
        ports="80,81",
        threads=32,
    )

    assert result["open_ports"] == [80, 81]
    assert peak_active == 1
