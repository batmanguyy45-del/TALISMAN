"""HTTP Parameter Pollution scanner — framework-aware duplicate parameter handling, WAF bypass, POST body pollution."""
from __future__ import annotations
import random
import string
from typing import Any
from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console

log = get_logger(__name__)

HPP_CANARY_PREFIX = "TLSMHPP"

SENSITIVE_PARAMS = [
    "role", "is_admin", "admin", "user", "uid",
    "id", "type", "status", "action", "mode",
    "debug", "test", "bypass", "disable",
    "amount", "price", "quantity", "total",
    "email", "username", "password", "token",
]

HPP_ENDPOINTS = [
    "/api/user", "/api/users", "/api/profile",
    "/api/login", "/api/auth",
    "/api/admin", "/api/settings",
    "/api/transfer", "/api/order",
    "/api/search", "/api/delete",
    "/api/update", "/api/config",
    "/admin", "/settings", "/profile",
]


def _build_hpp_tests(param: str) -> list[dict[str, Any]]:
    """Build HPP payloads with duplicate parameters using different values."""
    canary_evil = f"{HPP_CANARY_PREFIX}{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"
    canary_safe = f"{HPP_CANARY_PREFIX}{''.join(random.choices(string.ascii_lowercase + string.digits, k=8))}"

    return [
        {
            "description": "First-last value discrepancy",
            "params": [(param, canary_safe), (param, canary_evil)],
            "canary": canary_evil,
            "expected_position": "last",
        },
        {
            "description": "Triple duplicate parameters",
            "params": [(param, canary_safe), (param, "middle"), (param, canary_evil)],
            "canary": canary_evil,
            "expected_position": "last",
        },
    ]


async def _test_query_hpp(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test HPP in query string parameters."""
    findings: list[dict[str, Any]] = []
    test_url_base = url.rstrip("/") + endpoint

    for test_param in SENSITIVE_PARAMS[:8]:
        tests = _build_hpp_tests(test_param)

        for test in tests:
            # Build URL with duplicate parameters
            param_pairs = "&".join(f"{k}={v}" for k, v in test["params"])
            test_url = f"{test_url_base}?{param_pairs}"

            try:
                r = await client.get(test_url, timeout=8)
                resp_text = r.text.lower()
                canary = test["canary"].lower()

                if canary in resp_text:
                    findings.append({
                        "type": "query_hpp",
                        "endpoint": endpoint,
                        "parameter": test_param,
                        "description": test["description"],
                        "canary": test["canary"],
                        "evidence": f"Canary reflected at endpoint with duplicate {test_param} parameter",
                        "status": r.status_code,
                    })
                    break
            except Exception:
                pass

    return findings


async def _test_body_hpp(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test HPP in POST body (form-encoded and JSON)."""
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint
    canary = f"{HPP_CANARY_PREFIX}{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"

    # JSON array parameter test
    try:
        # Send raw JSON text: a Python dict cannot represent duplicate keys.
        payload = (
            '{"email":"test@example.invalid","role":"user",'
            f'"role":"{canary}"' + '}'
        )
        r = await client.post(test_url, data=payload,
            headers={"Content-Type": "application/json"}, timeout=8)
        if canary.lower() in r.text.lower()[:500]:
            findings.append({
                "type": "json_body_hpp",
                "endpoint": endpoint,
                "evidence": f"JSON duplicate 'role' parameter accepted, canary reflected",
                "canary": canary,
            })
    except Exception:
        pass

    # Form-encoded duplicate parameters
    safe_val = f"safe_{''.join(random.choices(string.ascii_lowercase, k=4))}"
    evil_val = canary

    for param in ["role", "admin", "status", "type"]:
        try:
            body = f"email=test@test.com&{param}={safe_val}&{param}={evil_val}"
            r = await client.post(test_url, data=body.encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=8)
            resp_text = r.text.lower()
            if evil_val.lower() in resp_text:
                findings.append({
                    "type": "form_body_hpp",
                    "endpoint": endpoint,
                    "parameter": param,
                    "canary": evil_val,
                    "evidence": f"Form-encoded duplicate {param} parameter accepted, canary reflected",
                })
                break
        except Exception:
            pass

    return findings


async def _test_header_hpp(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Duplicate headers are not testable through the mapping-based client API."""
    return []


async def _test_mixed_param_sources(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test HPP where param appears in BOTH query string AND POST body.

    Some frameworks parse different sources independently, allowing
    the same param in query AND body to be read differently by different layers.
    """
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint
    canary = f"{HPP_CANARY_PREFIX}{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"

    # Same param in both query string and POST body
    try:
        r = await client.post(
            f"{test_url}?role={canary}",
            data="email=test@test.com&role=user",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=8,
        )
        if canary.lower() in r.text.lower()[:500]:
            findings.append({
                "type": "mixed_source_hpp",
                "endpoint": endpoint,
                "parameter": "role",
                "canary": canary,
                "evidence": f"Same parameter 'role' sent in both query string and POST body. Canary from query string reflected.",
                "description": "Parameter pollution across query string and POST body",
            })
    except Exception:
        pass

    return findings


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Return HPP candidates only; reflection is not proof of parser confusion."""
    url = target if "://" in target else f"https://{target}"
    if scope is None:
        return {
            "target": url, "findings": [], "candidates": [], "count": 0,
            "candidate_count": 0, "error": "scope_enforcer_required",
        }
    scope.assert_in_scope(url)

    allow_post_probes = False
    try:
        scope.assert_destructive_allowed(url, "POST")
        allow_post_probes = True
    except ScopeViolationError:
        pass

    console.print(
        f"\n[module][+] HTTP Parameter Pollution Candidate Scanner[/module] -> [target]{url}[/target]"
    )
    candidates: list[dict[str, Any]] = []
    skipped_vectors: list[str] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=10, scope=scope) as client:
        for endpoint in HPP_ENDPOINTS:
            # Duplicate query parameters are read-only probes, but reflection
            # alone remains a candidate until semantic behavior is verified.
            for candidate in await _test_query_hpp(url, endpoint, client):
                candidates.append({
                    **candidate,
                    "confidence": "candidate",
                    "requires_semantic_verification": True,
                    "verification_required": (
                        "Compare the application's effective parameter value "
                        "against a single-value baseline and demonstrate an "
                        "authorization, validation, routing, or business-logic "
                        "difference. Canary reflection alone is insufficient."
                    ),
                })

            if not allow_post_probes:
                continue

            for candidate in await _test_body_hpp(url, endpoint, client):
                candidates.append({
                    **candidate,
                    "confidence": "candidate",
                    "requires_semantic_verification": True,
                    "verification_required": (
                        "Confirm the server's duplicate-key resolution and "
                        "demonstrate security-relevant impact using a disposable "
                        "test account and resource."
                    ),
                })

            for candidate in await _test_mixed_param_sources(url, endpoint, client):
                candidates.append({
                    **candidate,
                    "confidence": "candidate",
                    "requires_semantic_verification": True,
                    "verification_required": (
                        "Demonstrate that query/body precedence changes a "
                        "security decision, not merely that one value is echoed."
                    ),
                })

    # Duplicate headers cannot be represented by a dict: the previous test's
    # duplicate X-Forwarded-For keys collapsed to one value before transmission.
    skipped_vectors.append(
        "Duplicate-header HPP is not attempted: the current client header API "
        "uses mappings and cannot faithfully construct duplicate field lines."
    )
    if not allow_post_probes:
        skipped_vectors.append(
            "POST-body and mixed-source probes were skipped because explicit "
            "destructive-probe permission was not granted."
        )

    console.print(
        f"  HPP scan complete -- {len(candidates)} candidates; "
        "no confirmed vulnerabilities inferred from reflection"
    )
    return {
        "target": url,
        "findings": [],
        "candidates": candidates,
        "count": 0,
        "candidate_count": len(candidates),
        "post_probes_enabled": allow_post_probes,
        "skipped_vectors": skipped_vectors,
    }
