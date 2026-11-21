"""Tests ensuring database exposure findings require actual no-auth proof."""
from talisman.modules.misconfiguration.database_exposure import (
    _is_verified_unauthenticated,
)


def test_open_port_observation_is_not_a_vulnerability():
    observation = {
        "db": "MongoDB",
        "service_reachable": True,
        "auth_required": None,
        "verified_unauthenticated": False,
        "note": "TCP port is reachable; authentication was not tested",
    }
    assert not _is_verified_unauthenticated(observation)


def test_unauthenticated_redis_response_is_a_vulnerability():
    proof = {
        "db": "Redis",
        "auth_required": False,
        "verified_unauthenticated": True,
        "verification": "Unauthenticated INFO returned redis_version",
    }
    assert _is_verified_unauthenticated(proof)


def test_missing_verification_flag_is_not_a_vulnerability():
    legacy_result = {"db": "Elasticsearch", "auth_required": False}
    assert not _is_verified_unauthenticated(legacy_result)


def test_auth_required_true_is_not_a_no_auth_finding():
    protected = {
        "db": "Redis",
        "auth_required": True,
        "verified_unauthenticated": True,
    }
    assert not _is_verified_unauthenticated(protected)
