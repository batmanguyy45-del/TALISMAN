"""Unit tests for scope enforcement."""
import pytest
from talisman.engine.scope import ScopeEnforcer, ScopeConfig, ScopeViolationError


def _make_scope(include, exclude=None):
    cfg = ScopeConfig(include=include, exclude=exclude or [], service_allowlist=[])
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


def test_ipv6_cidr_scope():
    scope = _make_scope(["2001:db8::/32"])
    assert scope.is_in_scope("https://[2001:db8::1]/")
    assert not scope.is_in_scope("https://[2001:db9::1]/")


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
    cfg = ScopeConfig.from_target("https://example.com")
    scope = ScopeEnforcer(cfg)
    assert scope.is_in_scope("example.com")
    assert not scope.is_in_scope("api.example.com")


def test_from_target_accepts_explicit_wildcard():
    cfg = ScopeConfig.from_target("*.example.com")
    scope = ScopeEnforcer(cfg)
    assert scope.is_in_scope("api.example.com")
    assert not scope.is_in_scope("example.com")


def test_path_exclusion_without_scheme_applies_to_http_and_https():
    scope = _make_scope(
        ["example.com"],
        ["example.com/private/*"],
    )
    assert scope.is_in_scope("https://example.com/public")
    assert not scope.is_in_scope("https://example.com/private/account")
    assert not scope.is_in_scope("http://example.com/private/account")


def test_rejects_userinfo_and_malformed_urls():
    scope = _make_scope(["example.com"])
    assert not scope.is_in_scope("https://example.com@attacker.test/")
    assert not scope.is_in_scope("https://example.com:99999/")
    assert not scope.is_in_scope("file:///etc/passwd")


def test_url_path_scope_is_segment_bounded():
    scope = _make_scope(["https://example.com/api/*"])
    assert scope.is_in_scope("https://example.com/api/v1/users")
    assert not scope.is_in_scope("https://example.com/apix/v1")
    assert not scope.is_in_scope("https://example.com.evil.test/api/v1")


def test_url_scope_preserves_scheme_and_port():
    scope = _make_scope(["https://example.com:8443/api"])
    assert scope.is_in_scope("https://example.com:8443/api")
    assert scope.is_in_scope("https://example.com:8443/api/users")
    assert not scope.is_in_scope("http://example.com:8443/api")
    assert not scope.is_in_scope("https://example.com/api")


def test_write_methods_require_explicit_opt_in():
    scope = _make_scope(["example.com"])
    with pytest.raises(ScopeViolationError, match="POST blocked"):
        scope.assert_request_allowed("https://example.com/profile", "POST")


def test_delete_remains_blocked_even_when_writes_are_allowed():
    scope = ScopeEnforcer(ScopeConfig(
        include=["example.com"],
        service_allowlist=[],
        allow_state_changing_requests=True,
        avoid_destructive=True,
    ))
    scope.assert_request_allowed("https://example.com/profile", "PATCH")
    with pytest.raises(ScopeViolationError, match="DELETE blocked"):
        scope.assert_request_allowed("https://example.com/profile", "DELETE")


def test_only_explicit_service_hosts_are_allowed():
    scope = ScopeEnforcer(ScopeConfig(include=["example.com"], service_allowlist=["crt.sh"]))
    assert scope.is_service_allowed("https://crt.sh/?q=example.com")
    assert not scope.is_service_allowed("https://attacker.test/")
    with pytest.raises(ScopeViolationError):
        scope.assert_request_allowed("https://attacker.test/")



def test_encoded_path_traversal_cannot_bypass_exclusion():
    scope = _make_scope(
        ["example.com"],
        ["example.com/private/*"],
    )
    assert not scope.is_in_scope("https://example.com/public/%252e%252e/private/account")
    assert not scope.is_in_scope("https://example.com/public%252f..%252fprivate/account")


def test_control_characters_and_backslashes_are_rejected():
    scope = _make_scope(["example.com"])
    assert not scope.is_in_scope("https://example.com/\n.evil.test/")
    assert not scope.is_in_scope("https://example.com\\@evil.test/")



def test_wildcard_host_with_path_scope():
    scope = _make_scope(["https://*.example.com/api/*"])
    assert scope.is_in_scope("https://api.example.com/api/users")
    assert scope.is_in_scope("https://nested.api.example.com/api/users")
    assert not scope.is_in_scope("https://api.example.com/private/users")
    assert not scope.is_in_scope("http://api.example.com/api/users")
