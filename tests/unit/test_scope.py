"""Unit tests for scope enforcement."""
import pytest

from talisman.engine.scope import (
    ScopeConfig,
    ScopeEnforcer,
    ScopeViolationError,
    scope_context,
)


def _make_scope(include, exclude=None):
    return ScopeEnforcer(ScopeConfig(include=include, exclude=exclude or []))


def test_basic_domain():
    scope = _make_scope(["example.com"])
    assert scope.is_in_scope("example.com")
    assert scope.is_in_scope("https://example.com/path")
    assert not scope.is_in_scope("evil.com")


def test_wildcard_subdomain():
    scope = _make_scope(["*.example.com"])
    assert scope.is_in_scope("api.example.com")
    assert scope.is_in_scope("dev.api.example.com")
    assert not scope.is_in_scope("example.com")
    assert not scope.is_in_scope("notexample.com")


def test_exclude_overrides_include():
    scope = _make_scope(["*.example.com"], ["mail.example.com"])
    assert scope.is_in_scope("api.example.com")
    assert not scope.is_in_scope("mail.example.com")


def test_cidr_scope():
    scope = _make_scope(["192.168.1.0/24"])
    assert scope.is_in_scope("192.168.1.1")
    assert scope.is_in_scope("192.168.1.254")
    assert not scope.is_in_scope("192.168.2.1")


def test_filter_targets():
    scope = _make_scope(["example.com", "*.example.com"])
    targets = ["example.com", "api.example.com", "evil.com", "other.org"]
    filtered = scope.filter_targets(targets)
    assert "example.com" in filtered
    assert "api.example.com" in filtered
    assert "evil.com" not in filtered


def test_assert_raises_out_of_scope():
    scope = _make_scope(["example.com"])
    with pytest.raises(ScopeViolationError):
        scope.assert_in_scope("evil.com")


def test_from_target_is_exact_host_by_default():
    scope = ScopeEnforcer(ScopeConfig.from_target("https://example.com:8443/path"))
    assert scope.is_in_scope("https://example.com:8443/")
    assert not scope.is_in_scope("https://api.example.com:8443/")


def test_from_target_accepts_explicit_cidr():
    scope = ScopeEnforcer(ScopeConfig.from_target("192.168.10.0/24"))
    assert scope.is_in_scope("192.168.10.23")
    assert not scope.is_in_scope("192.168.11.23")


def test_url_path_scope_does_not_match_prefix_confusion():
    scope = _make_scope(["https://example.com/admin"])
    assert scope.is_in_scope("https://example.com/admin/users")
    assert not scope.is_in_scope("https://example.com/administrator")


def test_scope_context_binds_and_restores_scope():
    from talisman.engine.scope import get_active_scope

    scope = _make_scope(["example.com"])
    assert get_active_scope() is None
    with scope_context(scope):
        assert get_active_scope() is scope
    assert get_active_scope() is None
