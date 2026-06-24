"""Unit tests for all new/rewritten scanner, API, and network modules.

Tests module-level definitions (constants, data structures) and verifies
that the run() function is a proper async coroutine. HTTP-level behavior
is tested via integration tests or respx-based tests.
"""
from __future__ import annotations
import pytest


# ── nosqli ────────────────────────────────────────────────────────────────────

class TestNosqli:
    def test_import(self):
        import talisman.modules.scanner.nosqli as m
        assert hasattr(m, "NOSQLI_JSON_PAYLOADS")
        assert hasattr(m, "NOSQLI_QUERY_PAYLOADS")
        assert hasattr(m, "ENDPOINTS")
        assert len(m.NOSQLI_JSON_PAYLOADS) >= 3
        assert len(m.NOSQLI_QUERY_PAYLOADS) >= 3

    def test_run_is_coroutine(self):
        import talisman.modules.scanner.nosqli as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


# ── deserialization ───────────────────────────────────────────────────────────

class TestDeserialization:
    def test_import(self):
        import talisman.modules.scanner.deserialization as m
        assert hasattr(m, "DESERIALIZATION_PROBES")
        assert len(m.DESERIALIZATION_PROBES) >= 3
        assert hasattr(m, "DESERIALIZATION_SIGNATURES")

    def test_run_is_coroutine(self):
        import talisman.modules.scanner.deserialization as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


# ── websocket ─────────────────────────────────────────────────────────────────

class TestWebsocket:
    def test_import(self):
        import talisman.modules.scanner.websocket as m
        assert hasattr(m, "WS_PATHS")
        assert len(m.WS_PATHS) >= 3
        assert hasattr(m, "WS_INJECTION_PAYLOADS")

    def test_run_is_coroutine(self):
        import talisman.modules.scanner.websocket as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


# ── crlf ──────────────────────────────────────────────────────────────────────

class TestCrlf:
    def test_import(self):
        import talisman.modules.scanner.crlf as m
        assert hasattr(m, "CRLF_PAYLOADS")
        assert len(m.CRLF_PAYLOADS) >= 3
        assert hasattr(m, "CRLF_PARAMS")
        assert hasattr(m, "CRLF_HEADERS")

    def test_run_is_coroutine(self):
        import talisman.modules.scanner.crlf as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


# ── cache_deception ───────────────────────────────────────────────────────────

class TestCacheDeception:
    def test_import(self):
        import talisman.modules.scanner.cache_deception as m
        assert hasattr(m, "STATIC_EXTENSIONS")
        assert hasattr(m, "DYNAMIC_PATHS")
        assert len(m.STATIC_EXTENSIONS) >= 3

    def test_run_is_coroutine(self):
        import talisman.modules.scanner.cache_deception as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


# ── csp_evaluator ─────────────────────────────────────────────────────────────

class TestCspEvaluator:
    def test_import(self):
        import talisman.modules.scanner.csp_evaluator as m
        assert hasattr(m, "CSP_DIRECTIVES")
        assert hasattr(m, "DANGEROUS_CDNS")
        assert len(m.CSP_DIRECTIVES) >= 3

    def test_run_is_coroutine(self):
        import talisman.modules.scanner.csp_evaluator as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


# ── csrf ──────────────────────────────────────────────────────────────────────

class TestCsrf:
    def test_import(self):
        import talisman.modules.scanner.csrf as m
        assert hasattr(m, "STATE_CHANGING_ENDPOINTS")
        assert hasattr(m, "METHOD_OVERRIDE_VARIANTS")
        assert len(m.STATE_CHANGING_ENDPOINTS) >= 2

    def test_run_is_coroutine(self):
        import talisman.modules.scanner.csrf as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


# ── dangling_markup ───────────────────────────────────────────────────────────

class TestDanglingMarkup:
    def test_import(self):
        import talisman.modules.scanner.dangling_markup as m
        assert hasattr(m, "DANGLING_CANARY_PREFIX")
        assert hasattr(m, "DANGLING_ENDPOINTS")
        assert hasattr(m, "DANGLING_PAYLOADS")
        assert len(m.DANGLING_PAYLOADS) >= 3

    def test_run_is_coroutine(self):
        import talisman.modules.scanner.dangling_markup as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


# ── dep_confusion ─────────────────────────────────────────────────────────────

class TestDepConfusion:
    def test_import(self):
        import talisman.modules.scanner.dep_confusion as m
        assert hasattr(m, "PACKAGE_FILES")
        assert len(m.PACKAGE_FILES) >= 3

    def test_run_is_coroutine(self):
        import talisman.modules.scanner.dep_confusion as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


# ── dom_clobbering ────────────────────────────────────────────────────────────

class TestDomClobbering:
    def test_import(self):
        import talisman.modules.scanner.dom_clobbering as m
        assert hasattr(m, "DOM_CLOBBERING_PAYLOADS")
        assert len(m.DOM_CLOBBERING_PAYLOADS) >= 3

    def test_run_is_coroutine(self):
        import talisman.modules.scanner.dom_clobbering as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


# ── file_upload_scanner ───────────────────────────────────────────────────────

class TestFileUpload:
    def test_import(self):
        import talisman.modules.scanner.file_upload_scanner as m
        assert hasattr(m, "UPLOAD_ENDPOINTS")
        assert len(m.UPLOAD_ENDPOINTS) >= 3
        assert hasattr(m, "TEST_FILE_EXTENSIONS")

    def test_run_is_coroutine(self):
        import talisman.modules.scanner.file_upload_scanner as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


# ── git_exposure ──────────────────────────────────────────────────────────────

class TestGitExposure:
    def test_import(self):
        import talisman.modules.scanner.git_exposure as m
        assert hasattr(m, "EXPOSURE_PATHS")
        assert hasattr(m, "GIT_HEAD_PATTERNS")
        assert len(m.EXPOSURE_PATHS) >= 3

    def test_run_is_coroutine(self):
        import talisman.modules.scanner.git_exposure as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


# ── host_header ───────────────────────────────────────────────────────────────

class TestHostHeader:
    def test_import(self):
        import talisman.modules.scanner.host_header as m
        assert hasattr(m, "HOST_HEADER_VARIANTS")
        assert hasattr(m, "X_FORWARDED_HOST_VARIANTS")
        assert len(m.HOST_HEADER_VARIANTS) >= 3

    def test_run_is_coroutine(self):
        import talisman.modules.scanner.host_header as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


# ── hpp ───────────────────────────────────────────────────────────────────────

class TestHpp:
    def test_import(self):
        import talisman.modules.scanner.hpp as m
        assert hasattr(m, "HPP_CANARY_PREFIX")
        assert hasattr(m, "SENSITIVE_PARAMS")
        assert hasattr(m, "HPP_ENDPOINTS")
        assert len(m.SENSITIVE_PARAMS) >= 3

    def test_run_is_coroutine(self):
        import talisman.modules.scanner.hpp as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


# ── ldap_injection ────────────────────────────────────────────────────────────

class TestLdapInjection:
    def test_import(self):
        import talisman.modules.scanner.ldap_injection as m
        assert hasattr(m, "LDAP_CANARY_PREFIX")
        assert hasattr(m, "LDAP_WILDCARD_PAYLOADS")
        assert hasattr(m, "LDAP_AUTH_BYPASS_PAYLOADS")
        assert len(m.LDAP_WILDCARD_PAYLOADS) >= 3

    def test_run_is_coroutine(self):
        import talisman.modules.scanner.ldap_injection as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


# ── mass_assignment ───────────────────────────────────────────────────────────

class TestMassAssignment:
    def test_import(self):
        import talisman.modules.scanner.mass_assignment as m
        assert hasattr(m, "COMMON_PRIVILEGED_FIELDS")
        assert hasattr(m, "API_UPDATE_ENDPOINTS")
        assert len(m.COMMON_PRIVILEGED_FIELDS) >= 3

    def test_run_is_coroutine(self):
        import talisman.modules.scanner.mass_assignment as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


# ── parser_differential ───────────────────────────────────────────────────────

class TestParserDifferential:
    def test_import(self):
        import talisman.modules.scanner.parser_differential as m
        assert hasattr(m, "run")

    def test_run_is_coroutine(self):
        import talisman.modules.scanner.parser_differential as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


# ── second_order ──────────────────────────────────────────────────────────────

class TestSecondOrder:
    def test_import(self):
        import talisman.modules.scanner.second_order as m
        assert hasattr(m, "run")

    def test_run_is_coroutine(self):
        import talisman.modules.scanner.second_order as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


# ── ssji ──────────────────────────────────────────────────────────────────────

class TestSsji:
    def test_import(self):
        import talisman.modules.scanner.ssji as m
        assert hasattr(m, "SSJI_PAYLOADS")
        assert len(m.SSJI_PAYLOADS) >= 3

    def test_run_is_coroutine(self):
        import talisman.modules.scanner.ssji as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


# ── sspp ──────────────────────────────────────────────────────────────────────

class TestSspp:
    def test_import(self):
        import talisman.modules.scanner.sspp as m
        assert hasattr(m, "SSPP_CANARY_PREFIX")
        assert hasattr(m, "JSON_ENDPOINTS")
        assert len(m.JSON_ENDPOINTS) >= 3

    def test_run_is_coroutine(self):
        import talisman.modules.scanner.sspp as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


# ── unicode_attacks ───────────────────────────────────────────────────────────

class TestUnicodeAttacks:
    def test_import(self):
        import talisman.modules.scanner.unicode_attacks as m
        assert hasattr(m, "BIDI_CHARACTERS")
        assert hasattr(m, "INVISIBLE_CHARACTERS")
        assert hasattr(m, "HOMOGLYPH_SETS")
        assert len(m.BIDI_CHARACTERS) >= 3

    def test_run_is_coroutine(self):
        import talisman.modules.scanner.unicode_attacks as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


# ── verb_tampering ────────────────────────────────────────────────────────────

class TestVerbTampering:
    def test_import(self):
        import talisman.modules.scanner.verb_tampering as m
        assert hasattr(m, "run")

    def test_run_is_coroutine(self):
        import talisman.modules.scanner.verb_tampering as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


# ── smuggling ─────────────────────────────────────────────────────────────────

class TestSmuggling:
    def test_import(self):
        import talisman.modules.scanner.smuggling as m
        assert hasattr(m, "SMUGGLING_PREFIX")

    def test_run_is_coroutine(self):
        import talisman.modules.scanner.smuggling as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


# ── rate_limit ────────────────────────────────────────────────────────────────

class TestRateLimit:
    def test_import(self):
        import talisman.modules.scanner.rate_limit as m
        assert hasattr(m, "run")

    def test_run_is_coroutine(self):
        import talisman.modules.scanner.rate_limit as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


# ── API modules ───────────────────────────────────────────────────────────────

class TestOAuth:
    def test_import(self):
        import talisman.modules.api.oauth as m
        assert hasattr(m, "OAUTH_DISCOVERY_PATHS")
        assert hasattr(m, "PKCE_METHODS")
        assert len(m.OAUTH_DISCOVERY_PATHS) >= 3

    def test_run_is_coroutine(self):
        import talisman.modules.api.oauth as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


class TestGraphQL:
    def test_import(self):
        import talisman.modules.api.graphql as m
        assert hasattr(m, "COMMON_GQL_PATHS")
        assert hasattr(m, "INTROSPECTION_QUERY")
        assert len(m.COMMON_GQL_PATHS) >= 3

    def test_run_is_coroutine(self):
        import talisman.modules.api.graphql as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


class TestGrpc:
    def test_import(self):
        import talisman.modules.api.grpc as m
        assert hasattr(m, "GRPC_PORTS")
        assert hasattr(m, "GRPC_CONTENT_TYPES")
        assert hasattr(m, "REFLECTION_LIST_SERVICES")
        assert len(m.GRPC_PORTS) >= 3

    def test_run_is_coroutine(self):
        import talisman.modules.api.grpc as m
        import inspect; assert inspect.iscoroutinefunction(m.run)


# ── Network modules ───────────────────────────────────────────────────────────

class TestEmailSecurity:
    def test_import(self):
        import talisman.modules.network.email_security as m
        assert hasattr(m, "run")

    def test_run_is_coroutine(self):
        import talisman.modules.network.email_security as m
        import inspect; assert inspect.iscoroutinefunction(m.run)
