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
