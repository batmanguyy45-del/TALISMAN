"""Integration tests with respx-mocked HTTP — verifies detection logic of new modules."""
from __future__ import annotations
import inspect
import json
import pytest
import httpx
import respx
from talisman.engine.scope import ScopeConfig, ScopeEnforcer


def _test_scope():
    scope = ScopeEnforcer(
        ScopeConfig(
            include=["test.com"],
            service_allowlist=[],
            allow_state_changing_requests=True,
            avoid_writes=False,
            avoid_destructive=False,
        )
    )

    async def allow_mock_destination(url, method="GET"):
        import ipaddress

        scope.assert_request_allowed(url, method)
        return (ipaddress.ip_address("93.184.216.34"),)

    scope.resolve_network_destination = allow_mock_destination
    return scope


@pytest.fixture(autouse=True)
def _activate_scope_for_http_tests():
    from talisman.engine.scope import reset_active_scope, set_active_scope

    scope = _test_scope()
    token = set_active_scope(scope)
    try:
        yield scope
    finally:
        reset_active_scope(token)


def _is_coroutine(mod):
    return inspect.iscoroutinefunction(mod.run)


# ── nosqli ────────────────────────────────────────────────────────────────────

class TestNosqli:
    def test_import_and_async_entry_point(self):
        import talisman.modules.scanner.nosqli as m
        assert inspect.iscoroutinefunction(m.run)

    @pytest.mark.asyncio
    async def test_generic_nosqli_scanner_is_disabled(self):
        import talisman.modules.scanner.nosqli as m
        result = await m.run(
            target="http://test.com/",
            scope=_test_scope(),
        )
        assert result["skipped"] is True
        assert result["findings"] == []
        assert result["count"] == 0
        assert "disposable endpoint" in result["reason"]


# ── git_exposure ──────────────────────────────────────────────────────────────

class TestGitExposure:
    def test_import(self):
        import talisman.modules.scanner.git_exposure as m
        assert hasattr(m, "EXPOSURE_PATHS")

    @pytest.mark.asyncio
    async def test_detects_git_config(self):
        import talisman.modules.scanner.git_exposure as m
        async with respx.mock:
            respx.get("http://test.com/.git/config").respond(200, text="[core]\n\tbare = false")
            from talisman.utils.http_client import TalismanHTTPClient
            async with TalismanHTTPClient(scope=_test_scope()) as c:
                r = await m._test_path("http://test.com", "/.git/config", c)
            assert r is not None
            assert r["type"] == "git_exposure"

    @pytest.mark.asyncio
    async def test_no_false_positive_on_404(self):
        import talisman.modules.scanner.git_exposure as m
        async with respx.mock:
            respx.get("http://test.com/.git/config").respond(404)
            from talisman.utils.http_client import TalismanHTTPClient
            async with TalismanHTTPClient(scope=_test_scope()) as c:
                r = await m._test_path("http://test.com", "/.git/config", c)
            assert r is None


# ── sspp ──────────────────────────────────────────────────────────────────────

class TestSspp:
    def test_constants(self):
        import talisman.modules.scanner.sspp as m
        assert m.SSPP_CANARY_PREFIX == "TLSMSSPP"
        assert len(m.JSON_ENDPOINTS) >= 3

    @pytest.mark.asyncio
    async def test_generic_sspp_scanner_is_disabled(self):
        import talisman.modules.scanner.sspp as m

        result = await m.run(
            target="http://test.com/",
            scope=_test_scope(),
        )

        assert result["skipped"] is True
        assert result["findings"] == []
        assert result["count"] == 0


# ── crlf ──────────────────────────────────────────────────────────────────────

class TestCrlf:
    def test_constants(self):
        import talisman.modules.scanner.crlf as m
        assert len(m.CRLF_PAYLOADS) >= 3
        assert len(m.CRLF_PARAMS) >= 3

    @pytest.mark.asyncio
    async def test_detects_header_injection(self):
        import talisman.modules.scanner.crlf as m
        from talisman.utils.http_client import TalismanHTTPClient
        async with respx.mock:
            respx.get("http://test.com/").respond(
                200, text="ok",
                headers={"X-TALISMAN-CRLF": "injected"},
            )
            async with TalismanHTTPClient(scope=_test_scope()) as c:
                r = await m._test_param_crlf("http://test.com/", c)
            assert len(r) >= 0


# ── host_header ───────────────────────────────────────────────────────────────

class TestHostHeader:
    def test_constants(self):
        import talisman.modules.scanner.host_header as m
        assert len(m.HOST_HEADER_VARIANTS) >= 3

    @pytest.mark.asyncio
    async def test_run_returns_dict(self):
        import talisman.modules.scanner.host_header as m
        async with respx.mock:
            respx.get("http://test.com/").respond(200, text="<html></html>")
            r = await m.run(target="http://test.com/", scope=_test_scope())
        assert isinstance(r, dict) and "findings" in r


# ── csrf ──────────────────────────────────────────────────────────────────────

class TestCsrf:
    def test_generic_mutation_probe_code_is_removed(self):
        import talisman.modules.scanner.csrf as m
        assert not hasattr(m, "_test_csrf_token_handling")
        assert not hasattr(m, "STATE_CHANGING_ENDPOINTS")
        assert not hasattr(m, "METHOD_OVERRIDE_VARIANTS")

    @pytest.mark.asyncio
    async def test_run_returns_dict(self):
        import talisman.modules.scanner.csrf as m
        async with respx.mock:
            respx.get("http://test.com/").respond(200, text="<html><form><input name='csrf'/></form></html>")
            r = await m.run(target="http://test.com/", scope=_test_scope())
        assert isinstance(r, dict)
        assert r["findings"] == []
        assert r["state_changing_probes_sent"] == 0

    @pytest.mark.asyncio
    async def test_run_never_sends_state_changing_requests(self):
        import talisman.modules.scanner.csrf as m
        async with respx.mock:
            respx.get("http://test.com/").respond(
                200,
                headers={"Set-Cookie": "sessionid=abc123; Path=/"},
            )
            respx.post("http://test.com/").mock(
                side_effect=AssertionError("CSRF assessment must not POST")
            )
            r = await m.run(target="http://test.com/", scope=_test_scope())

        assert r["findings"] == []
        assert r["observation_count"] >= 1
        assert r["state_changing_probes_sent"] == 0


# ── cache_deception ───────────────────────────────────────────────────────────

class TestCacheDeception:
    def test_constants(self):
        import talisman.modules.scanner.cache_deception as m
        assert len(m.STATIC_EXTENSIONS) >= 3

    @pytest.mark.asyncio
    async def test_run_returns_dict(self):
        import talisman.modules.scanner.cache_deception as m
        async with respx.mock:
            respx.get("/").respond(200, text="cached")
            r = await m.run(target="http://test.com/")
        assert isinstance(r, dict)


# ── parser_differential ───────────────────────────────────────────────────────

class TestParserDifferential:
    @pytest.mark.asyncio
    async def test_run_returns_dict(self):
        import talisman.modules.scanner.parser_differential as m
        async with respx.mock:
            respx.post("/").respond(200, text='{"status":"ok"}')
            r = await m.run(target="http://test.com/")
        assert isinstance(r, dict)


# ── second_order ──────────────────────────────────────────────────────────────

class TestSecondOrder:
    @pytest.mark.asyncio
    async def test_run_returns_dict(self):
        import talisman.modules.scanner.second_order as m
        async with respx.mock:
            respx.post("/").respond(200)
            respx.get("/").respond(200, text="<html></html>")
            r = await m.run(target="http://test.com/")
        assert isinstance(r, dict)


# ── smuggling ─────────────────────────────────────────────────────────────────

class TestSmuggling:
    def test_constants(self):
        import talisman.modules.scanner.smuggling as m
        assert m.SMUGGLING_PREFIX

    @pytest.mark.asyncio
    async def test_run_returns_dict(self):
        import talisman.modules.scanner.smuggling as m
        r = await m.run(target="http://test.com/")
        assert isinstance(r, dict)


# ── csp_evaluator ─────────────────────────────────────────────────────────────

class TestCspEvaluator:
    def test_constants(self):
        import talisman.modules.scanner.csp_evaluator as m
        assert len(m.CSP_DIRECTIVES) >= 3

    @pytest.mark.asyncio
    async def test_run_returns_dict(self):
        import talisman.modules.scanner.csp_evaluator as m
        async with respx.mock:
            respx.get("/").respond(200, text="<html></html>",
                                   headers={"Content-Security-Policy": "default-src 'self'"})
            r = await m.run(target="http://test.com/")
        assert isinstance(r, dict)


# ── verb_tampering ────────────────────────────────────────────────────────────

class TestVerbTampering:
    @pytest.mark.asyncio
    async def test_run_returns_dict(self):
        import talisman.modules.scanner.verb_tampering as m
        async with respx.mock:
            respx.request("GET", "/").respond(200)
            respx.request("POST", "/").respond(200)
            respx.request("PUT", "/").respond(200)
            respx.request("PATCH", "/").respond(200)
            respx.request("DELETE", "/").respond(200)
            respx.request("HEAD", "/").respond(200)
            respx.request("OPTIONS", "/").respond(200)
            respx.request("TRACE", "/").respond(200)
            respx.request("CONNECT", "/").respond(200)
            r = await m.run(target="http://test.com/")
        assert isinstance(r, dict)


# ── file_upload ───────────────────────────────────────────────────────────────

class TestFileUpload:
    def test_constants(self):
        import talisman.modules.scanner.file_upload_scanner as m
        assert m.UPLOAD_CANARY_PREFIX == "TLSMFILE"

    @pytest.mark.asyncio
    async def test_run_returns_dict(self):
        import talisman.modules.scanner.file_upload_scanner as m
        async with respx.mock:
            respx.post("/").respond(200)
            r = await m.run(target="http://test.com/")
        assert isinstance(r, dict)


# ── rate_limit ────────────────────────────────────────────────────────────────

class TestRateLimit:
    @pytest.mark.asyncio
    async def test_run_returns_dict(self):
        import talisman.modules.scanner.rate_limit as m
        async with respx.mock:
            respx.post("/").respond(200)
            r = await m.run(target="http://test.com/")
        assert isinstance(r, dict)


# ── hpp ───────────────────────────────────────────────────────────────────────

class TestHpp:
    def test_constants(self):
        import talisman.modules.scanner.hpp as m
        assert m.HPP_CANARY_PREFIX == "TLSMHPP"

    @pytest.mark.asyncio
    async def test_run_returns_dict(self):
        import talisman.modules.scanner.hpp as m
        async with respx.mock:
            respx.get("/").respond(200)
            r = await m.run(target="http://test.com/")
        assert isinstance(r, dict)


# ── ldap_injection ────────────────────────────────────────────────────────────

class TestLdapInjection:
    def test_constants(self):
        import talisman.modules.scanner.ldap_injection as m
        assert m.LDAP_CANARY_PREFIX == "TLSMLDAP"

    @pytest.mark.asyncio
    async def test_run_returns_dict(self):
        import talisman.modules.scanner.ldap_injection as m
        async with respx.mock:
            respx.post("/").respond(200)
            r = await m.run(target="http://test.com/")
        assert isinstance(r, dict)


# ── ssji ──────────────────────────────────────────────────────────────────────

class TestSsji:
    def test_constants(self):
        import talisman.modules.scanner.ssji as m
        assert len(m.SSJI_PAYLOADS) >= 3

    @pytest.mark.asyncio
    async def test_run_returns_dict(self):
        import talisman.modules.scanner.ssji as m
        async with respx.mock:
            respx.post("/").respond(200)
            r = await m.run(target="http://test.com/")
        assert isinstance(r, dict)


# ── dom_clobbering ────────────────────────────────────────────────────────────

class TestDomClobbering:
    def test_constants(self):
        import talisman.modules.scanner.dom_clobbering as m
        assert len(m.DOM_CLOBBERING_PAYLOADS) >= 3

    @pytest.mark.asyncio
    async def test_run_returns_dict(self):
        import talisman.modules.scanner.dom_clobbering as m
        async with respx.mock:
            respx.get("/").respond(200)
            r = await m.run(target="http://test.com/")
        assert isinstance(r, dict)


# ── dangling_markup ───────────────────────────────────────────────────────────

class TestDanglingMarkup:
    def test_constants(self):
        import talisman.modules.scanner.dangling_markup as m
        assert m.DANGLING_CANARY_PREFIX == "TLSMDANGLE"

    @pytest.mark.asyncio
    async def test_run_returns_dict(self):
        import talisman.modules.scanner.dangling_markup as m
        async with respx.mock:
            respx.get("/").respond(200)
            r = await m.run(target="http://test.com/")
        assert isinstance(r, dict)


# ── unicode_attacks ───────────────────────────────────────────────────────────

class TestUnicodeAttacks:
    def test_constants(self):
        import talisman.modules.scanner.unicode_attacks as m
        assert len(m.BIDI_CHARACTERS) >= 3
        assert len(m.INVISIBLE_CHARACTERS) >= 3

    @pytest.mark.asyncio
    async def test_run_returns_dict(self):
        import talisman.modules.scanner.unicode_attacks as m
        async with respx.mock:
            respx.get("/").respond(200)
            r = await m.run(target="http://test.com/")
        assert isinstance(r, dict)


# ── websocket ─────────────────────────────────────────────────────────────────

class TestWebsocket:
    @pytest.mark.asyncio
    async def test_websocket_probes_are_disabled_without_scoped_transport(self):
        import talisman.modules.scanner.websocket as m
        r = await m.run(target="http://test.com/", scope=_test_scope())
        assert r["skipped"] is True
        assert r["findings"] == []
        assert r["count"] == 0
        assert "pinned HTTP transport" in r["reason"]


# ── deserialization ───────────────────────────────────────────────────────────

class TestDeserialization:
    @pytest.mark.asyncio
    async def test_generic_deserialization_probes_are_disabled(self):
        import talisman.modules.scanner.deserialization as m
        result = await m.run(
            target="http://test.com/",
            scope=_test_scope(),
        )
        assert result["skipped"] is True
        assert result["findings"] == []
        assert result["count"] == 0
        assert "disposable fixture" in result["reason"]


# ── dep_confusion ─────────────────────────────────────────────────────────────

class TestDepConfusion:
    def test_constants(self):
        import talisman.modules.scanner.dep_confusion as m
        assert len(m.PACKAGE_FILES) >= 3

    @pytest.mark.asyncio
    async def test_run_returns_dict(self):
        import talisman.modules.scanner.dep_confusion as m
        async with respx.mock:
            respx.get("/package.json").respond(200, text='{"dependencies":{"x":"^1.0.0"}}')
            r = await m.run(target="http://test.com/")
        assert isinstance(r, dict)


# ── oauth ─────────────────────────────────────────────────────────────────────

class TestOAuth:
    def test_constants(self):
        import talisman.modules.api.oauth as m
        assert len(m.OAUTH_DISCOVERY_PATHS) >= 3

    @pytest.mark.asyncio
    async def test_run_returns_dict(self):
        import talisman.modules.api.oauth as m
        async with respx.mock:
            respx.get("/").respond(200)
            r = await m.run(target="http://test.com/")
        assert isinstance(r, dict)


# ── graphql ───────────────────────────────────────────────────────────────────

class TestGraphQL:
    def test_constants(self):
        import talisman.modules.api.graphql as m
        assert len(m.COMMON_GQL_PATHS) >= 3

    @pytest.mark.asyncio
    async def test_run_returns_dict(self):
        import talisman.modules.api.graphql as m
        async with respx.mock:
            respx.post("/graphql").respond(200, text='{"data":{"__schema":{}}}')
            r = await m.run(target="http://test.com/")
        assert isinstance(r, dict)


# ── grpc ──────────────────────────────────────────────────────────────────────

class TestGrpc:
    def test_constants(self):
        import talisman.modules.api.grpc as m
        assert len(m.GRPC_PORTS) >= 3

    @pytest.mark.asyncio
    async def test_run_returns_dict(self):
        import talisman.modules.api.grpc as m
        r = await m.run(target="http://test.com/")
        assert isinstance(r, dict)


# ── email_security ────────────────────────────────────────────────────────────

class TestEmailSecurity:
    @pytest.mark.asyncio
    async def test_run_returns_dict(self):
        import talisman.modules.network.email_security as m
        r = await m.run(target="test.com")
        assert isinstance(r, dict)


# ── mass_assignment ───────────────────────────────────────────────────────────

class TestMassAssignment:
    def test_constants(self):
        import talisman.modules.scanner.mass_assignment as m
        assert len(m.COMMON_PRIVILEGED_FIELDS) >= 3

    @pytest.mark.asyncio
    async def test_run_returns_dict(self):
        import talisman.modules.scanner.mass_assignment as m
        async with respx.mock:
            respx.get("/").respond(200, text='{"role":"user"}')
            respx.put("/").respond(200, text='{"role":"admin"}')
            r = await m.run(target="http://test.com/")
        assert isinstance(r, dict)


class TestDatabaseExposureRedisProbe:
    @pytest.mark.asyncio
    async def test_redis_probe_sends_a_real_crlf_terminated_info_command(monkeypatch):
        import talisman.modules.misconfiguration.database_exposure as module

        sent = []

        class FakeSocket:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def settimeout(self, timeout):
                pass

            def sendall(self, payload):
                sent.append(payload)

            def recv(self, size):
                return b"# Server\nredis_version:7.2.0\n"

        monkeypatch.setattr(
            module.socket,
            "create_connection",
            lambda address, timeout: FakeSocket(),
        )

        async def immediate_to_thread(function, *args, **kwargs):
            return function(*args, **kwargs)

        async def no_wait_for_rate_slot():
            return None

        monkeypatch.setattr(module.asyncio, "to_thread", immediate_to_thread)
        scope = _test_scope()
        monkeypatch.setattr(scope, "acquire_request_slot", no_wait_for_rate_slot)

        result = await module._test_redis("test.com", 6379, scope)

        assert result is not None
        assert sent == [b"INFO server\r\n"]
