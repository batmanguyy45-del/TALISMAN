"""Unit tests for scope enforcement."""
import pytest

from talisman.engine.scope import ScopeConfig, ScopeEnforcer, ScopeViolationError


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



def test_scope_rejects_malformed_hostname():
    with pytest.raises(ValueError):
        ScopeEnforcer(
            ScopeConfig(
                include=["https://example.com@attacker.test"],
                service_allowlist=[],
            )
        )
    with pytest.raises(ValueError):
        ScopeEnforcer(ScopeConfig(include=["bad_host.example"], service_allowlist=[]))


def test_scope_rejects_non_boolean_policy_values(tmp_path):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        "include:\n  - example.com\nrestrictions:\n  allow_state_changing_requests: 'false'\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="must be true or false"):
        ScopeConfig.from_file(scope_file)


def test_scope_rejects_excessive_request_rate(tmp_path):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        "include:\n  - example.com\nrestrictions:\n  max_requests_per_second: 1000\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="no greater than"):
        ScopeConfig.from_file(scope_file)



def test_passive_service_hosts_remain_read_only_when_active_testing_enabled():
    scope = ScopeEnforcer(ScopeConfig(
        include=["example.com"],
        service_allowlist=["registry.npmjs.org"],
        allow_state_changing_requests=True,
        avoid_writes=False,
        avoid_destructive=False,
    ))
    scope.assert_request_allowed("https://registry.npmjs.org/package", "GET")
    with pytest.raises(ScopeViolationError, match="read-only data sources"):
        scope.assert_request_allowed("https://registry.npmjs.org/package", "POST")


def test_destructive_operations_need_separate_opt_in():
    scope = ScopeEnforcer(ScopeConfig(
        include=["example.com"],
        service_allowlist=[],
        allow_state_changing_requests=True,
        avoid_writes=False,
        avoid_destructive=True,
    ))
    with pytest.raises(ScopeViolationError, match="Destructive probe blocked"):
        scope.assert_destructive_allowed("https://example.com/api", "POST")

    allowed = ScopeEnforcer(ScopeConfig(
        include=["example.com"],
        service_allowlist=[],
        allow_state_changing_requests=True,
        avoid_writes=False,
        avoid_destructive=False,
    ))
    allowed.assert_destructive_allowed("https://example.com/api", "POST")



@pytest.mark.asyncio
async def test_dns_resolving_to_private_address_is_blocked(monkeypatch):
    scope = _make_scope(["example.com"])

    async def fake_resolve(host, port):
        return {ipaddress.ip_address("127.0.0.1")}

    import ipaddress

    monkeypatch.setattr(scope, "_resolve_host_addresses", fake_resolve)
    with pytest.raises(ScopeViolationError, match="non-public address"):
        await scope.assert_network_destination_allowed("https://example.com/")


@pytest.mark.asyncio
async def test_private_dns_address_is_allowed_only_when_ip_is_explicitly_scoped(monkeypatch):
    import ipaddress

    scope = _make_scope(["example.com", "10.20.0.0/16"])

    async def fake_resolve(host, port):
        return {ipaddress.ip_address("10.20.4.12")}

    monkeypatch.setattr(scope, "_resolve_host_addresses", fake_resolve)
    await scope.assert_network_destination_allowed("https://example.com/")


@pytest.mark.asyncio
async def test_public_dns_addresses_are_allowed(monkeypatch):
    import ipaddress

    scope = _make_scope(["example.com"])

    async def fake_resolve(host, port):
        return {ipaddress.ip_address("93.184.216.34")}

    monkeypatch.setattr(scope, "_resolve_host_addresses", fake_resolve)
    await scope.assert_network_destination_allowed("https://example.com/")


@pytest.mark.asyncio
async def test_private_literal_requires_explicit_ip_scope():
    scope = _make_scope(["example.com"])
    with pytest.raises(ScopeViolationError, match="non-public address"):
        await scope.assert_network_destination_allowed("http://127.0.0.1/")


@pytest.mark.asyncio
async def test_private_literal_is_allowed_when_explicitly_scoped():
    scope = _make_scope(["10.0.0.1"])
    await scope.assert_network_destination_allowed("http://10.0.0.1/")
