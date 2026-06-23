"""Unit tests for scope enforcement."""
import pytest
from talisman.engine.scope import ScopeEnforcer, ScopeConfig, ScopeViolationError

def _make_scope(include, exclude=None):
 cfg = ScopeConfig(include=include, exclude=exclude or [])
 return ScopeEnforcer(cfg)

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

def test_from_target():
 cfg = ScopeConfig.from_target("https://example.com")
 scope = ScopeEnforcer(cfg)
 assert scope.is_in_scope("example.com")
 assert scope.is_in_scope("api.example.com")
