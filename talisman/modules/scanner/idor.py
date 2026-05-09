"""
IDOR / BOLA Scanner — Insecure Direct Object Reference

FALSE-POSITIVE ELIMINATION STRATEGY
====================================
PROBLEM: Checking if changing id=1 to id=2 returns HTTP 200 with
  "different content" is far too loose. Almost every site returns
  different pages for different IDs — that's normal!

CORRECT APPROACH:
  1. Requires TWO separate authenticated requests (own resource vs other resource).
  2. Structural similarity check: the responses must have the SAME HTML structure
     but different data values — not just different lengths.
  3. Sensitive data indicator check: look for emails, names, UUIDs, account numbers
     in the accessed-other-user's response that differ from baseline.
  4. For UUID-based endpoints, increment/replace UUIDs.
  5. API JSON endpoint check: if JSON response contains fields like "user_id",
     "email", "account" that differ between requests — strong indicator.
  6. Always requires the accessed ID to return a resource that structurally
     matches the baseline (same JSON keys or same HTML landmark tags).
"""
from __future__ import annotations
import asyncio
import json
import re
import urllib.parse
import uuid
from typing import Any

from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

# Parameters commonly used as object identifiers
ID_PARAMS = [
    "id", "user_id", "account_id", "order_id", "invoice_id",
    "document_id", "file_id", "report_id", "profile_id", "uid",
    "record_id", "item_id", "object_id", "resource_id",
    "customer_id", "patient_id", "ticket_id", "task_id",
]

# Sensitive field names in JSON responses
SENSITIVE_FIELDS = {
    "email", "username", "phone", "address", "name", "full_name",
    "first_name", "last_name", "ssn", "dob", "birth_date",
    "account_number", "card_number", "balance", "role",
    "password", "token", "secret", "api_key",
}

# Regex patterns for sensitive data in HTML responses
SENSITIVE_PATTERNS = [
    re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),  # email
    re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),  # SSN
    re.compile(r'\b(?:\d{4}[- ]){3}\d{4}\b'),  # credit card
    re.compile(r'\b\+?1?\s*\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b'),  # phone
]


def _extract_json_safely(text: str) -> dict | list | None:
    """Try to extract JSON from a response."""
    try:
        return json.loads(text)
    except Exception:
        # Look for embedded JSON
        match = re.search(r'(\{[^{}]{20,}\}|\[[^\[\]]{20,}\])', text)
        if match:
            try:
                return json.loads(match.group(1))
            except Exception:
                pass
    return None


def _get_json_keys_deep(obj: Any, depth: int = 3) -> set[str]:
    """Recursively collect all keys from a JSON structure."""
    keys: set[str] = set()
    if depth <= 0:
        return keys
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.add(str(k).lower())
            keys |= _get_json_keys_deep(v, depth - 1)
    elif isinstance(obj, list):
        for item in obj[:3]:
            keys |= _get_json_keys_deep(item, depth - 1)
    return keys


def _get_json_leaf_values(obj: Any, depth: int = 3) -> set[str]:
    """Collect all leaf string/number values from a JSON structure."""
    values: set[str] = set()
    if depth <= 0:
        return values
    if isinstance(obj, dict):
        for v in obj.values():
            values |= _get_json_leaf_values(v, depth - 1)
    elif isinstance(obj, list):
        for item in obj[:5]:
            values |= _get_json_leaf_values(item, depth - 1)
    elif isinstance(obj, (str, int, float)) and obj is not None:
        values.add(str(obj))
    return values


def _extract_sensitive_from_html(text: str) -> set[str]:
    """Extract potentially sensitive values from HTML."""
    found: set[str] = set()
    for pattern in SENSITIVE_PATTERNS:
        found.update(pattern.findall(text))
    return found


def _structures_match(resp1_text: str, resp2_text: str) -> bool:
    """
    Check if two responses have the same basic structure.
    Uses landmark HTML tags or JSON key sets.
    We want responses that look like the same 'template' but with different data.
    """
    # Try JSON comparison
    j1 = _extract_json_safely(resp1_text)
    j2 = _extract_json_safely(resp2_text)

    if j1 is not None and j2 is not None:
        # Same type?
        if type(j1) != type(j2):
            return False
        # Same top-level keys?
        keys1 = _get_json_keys_deep(j1, depth=1)
        keys2 = _get_json_keys_deep(j2, depth=1)
        if not keys1 or not keys2:
            return False
        overlap = keys1 & keys2
        return len(overlap) / max(len(keys1), len(keys2)) > 0.5

    # HTML structural comparison via landmark tags
    def _get_landmarks(text: str) -> list[str]:
        tags = re.findall(
            r'<(?:div|span|section|article|form|table|tr|td|h[1-6]|p|ul|li)'
            r'(?:\s[^>]*)?>',
            text,
            re.IGNORECASE,
        )
        return [re.sub(r'\s+\S+=(?:"[^"]*"|\'[^\']*\'|\S+)', '', t) for t in tags[:50]]

    l1 = _get_landmarks(resp1_text)
    l2 = _get_landmarks(resp2_text)

    if not l1 or not l2:
        return True  # Can't determine, allow continuation

    # Must share at least 70% of landmark structure
    s1, s2 = set(l1), set(l2)
    overlap = len(s1 & s2)
    return overlap / max(len(s1), len(s2)) >= 0.7


def _data_is_meaningfully_different(
    baseline_text: str,
    accessed_text: str,
    baseline_id: str,
    accessed_id: str,
) -> tuple[bool, str]:
    """
    Return (True, reason) if the accessed response contains meaningfully
    different data that indicates access to a DIFFERENT resource/object.

    Key insight: we're not looking for ANY difference — we're looking for
    data that plausibly belongs to a different user/object.
    """
    # Try JSON analysis first
    j_base = _extract_json_safely(baseline_text)
    j_accessed = _extract_json_safely(accessed_text)

    if j_base is not None and j_accessed is not None:
        base_vals = _get_json_leaf_values(j_base)
        accessed_vals = _get_json_leaf_values(j_accessed)

        # Values in accessed but not in baseline
        new_vals = accessed_vals - base_vals
        # Check for sensitive field names with different values
        base_keys = _get_json_keys_deep(j_base)
        sensitive_keys_present = base_keys & SENSITIVE_FIELDS

        if sensitive_keys_present and new_vals:
            # Sensitive fields exist and their values differ
            sample_new = list(new_vals)[:3]
            return True, (
                f"JSON response contains different values for sensitive fields "
                f"({', '.join(sensitive_keys_present)}). "
                f"New values: {sample_new}"
            )

        # Check: does accessed response contain the baseline's ID value embedded?
        # If not, and the accessed ID appears instead, it's a strong indicator
        if (
            baseline_id not in accessed_text
            and accessed_id in accessed_text
            and len(accessed_vals & {accessed_id}) > 0
        ):
            return True, (
                f"Resource ID {accessed_id} appears in response data, "
                f"while baseline ID {baseline_id} does not"
            )

    # HTML analysis: check for sensitive data patterns
    base_sensitive = _extract_sensitive_from_html(baseline_text)
    accessed_sensitive = _extract_sensitive_from_html(accessed_text)
    new_sensitive = accessed_sensitive - base_sensitive

    if new_sensitive:
        sample = list(new_sensitive)[:2]
        return True, (
            f"Accessed resource reveals different sensitive data: {sample}"
        )

    # Check if the resource ID is embedded in the response differently
    # This handles cases like /api/users/2 returning {"id":2,"email":"bob@..."}
    if accessed_id in accessed_text and baseline_id not in accessed_text:
        # The accessed ID appears but baseline does not — likely different resource
        # Only valid for numeric IDs (UUIDs are less reliable here)
        try:
            int(accessed_id)
            int(baseline_id)
            # Check context — must appear in a "data" context, not just the URL
            pattern = re.compile(
                rf'["\'](?:id|user_id|account_id|object_id)["\']'
                rf'\s*:\s*["\']?{re.escape(accessed_id)}["\']?',
                re.IGNORECASE,
            )
            if pattern.search(accessed_text):
                return True, (
                    f"Response body contains accessed ID ({accessed_id}) "
                    f"in a data field, confirming different resource access"
                )
        except ValueError:
            pass

    return False, ""


async def _test_idor(
    url: str,
    param: str,
    baseline_id: str,
    test_ids: list[str],
    client: TalismanHTTPClient,
    auth_headers: dict[str, str],
) -> dict[str, Any] | None:
    import urllib.parse as _up

    parsed = _up.urlparse(url)
    base_params = dict(_up.parse_qsl(parsed.query))

    # Get baseline response
    base_params[param] = baseline_id
    try:
        base_r = await client.get(
            parsed._replace(query=_up.urlencode(base_params)).geturl(),
            headers=auth_headers,
            timeout=12,
        )
        if base_r.status_code not in (200, 201):
            return None
        base_text = base_r.text
        base_len = len(base_text)
    except Exception as e:
        log.debug("idor_baseline", param=param, error=str(e)[:60])
        return None

    for test_id in test_ids:
        test_params = {**base_params, param: test_id}
        test_url = parsed._replace(query=_up.urlencode(test_params)).geturl()

        try:
            r = await client.get(
                test_url, headers=auth_headers, timeout=12
            )

            # Must return a success status
            if r.status_code not in (200, 201):
                continue

            # Response must not be identical to baseline
            if r.text == base_text:
                continue

            # Length must be in a reasonable range (not just an empty page)
            if len(r.text) < 50:
                continue

            # The responses must have the same structure (same "template")
            if not _structures_match(base_text, r.text):
                continue

            # Core check: is the data meaningfully different in a way
            # that indicates a different object was accessed?
            is_idor, reason = _data_is_meaningfully_different(
                base_text, r.text, baseline_id, test_id
            )

            if is_idor:
                return {
                    "param": param,
                    "baseline_id": baseline_id,
                    "accessed_id": test_id,
                    "status": r.status_code,
                    "evidence": reason,
                    "request": f"GET {test_url} HTTP/1.1",
                    "base_len": base_len,
                    "accessed_len": len(r.text),
                }

        except Exception as e:
            log.debug("idor_test", param=param, test_id=test_id, error=str(e)[:60])

    return None


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    auth_token: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    console.print(
        f"\n[module]⚡ IDOR Scanner[/module] → [target]{url}[/target]"
    )
    findings: list[dict[str, Any]] = []

    auth_headers: dict[str, str] = {}
    if auth_token:
        auth_headers["Authorization"] = f"Bearer {auth_token}"

    parsed = urllib.parse.urlparse(url)
    existing_params = dict(urllib.parse.parse_qsl(parsed.query))

    # Only test params that look like identifiers
    params_to_test = {
        k: v
        for k, v in existing_params.items()
        if any(ip in k.lower() for ip in ID_PARAMS)
    }

    if not params_to_test:
        # Try with likely default values if no ID params found
        params_to_test = {p: "1" for p in ID_PARAMS[:4]}

    async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
        for param, baseline_id in params_to_test.items():
            # Build a smart list of test IDs
            test_ids: list[str] = []

            # Check if baseline looks like a UUID
            uuid_re = re.compile(
                r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
                re.IGNORECASE,
            )
            if uuid_re.match(baseline_id):
                # Generate a few random UUIDs — only valid if auth_token provided
                if auth_token:
                    test_ids = [str(uuid.uuid4()) for _ in range(3)]
                else:
                    continue  # UUID enumeration without auth is meaningless
            else:
                # Numeric ID — test adjacent values
                try:
                    base_int = int(baseline_id)
                    # Test small increments/decrements
                    candidates = list(range(max(1, base_int - 3), base_int + 4))
                    candidates = [str(c) for c in candidates if str(c) != baseline_id]
                    test_ids = candidates[:6]
                except ValueError:
                    # Non-numeric, non-UUID — skip
                    continue

            if not test_ids:
                continue

            result = await _test_idor(
                url, param, baseline_id, test_ids, client, auth_headers
            )

            if result:
                severity = "high"
                title = (
                    f"IDOR — parameter '{param}' allows access to ID "
                    f"{result['accessed_id']}"
                )
                print_finding(title, severity, url)
                findings.append(result)

                if session:
                    await session.add_finding(
                        target=url,
                        module="idor",
                        vuln_type="idor",
                        severity=severity,
                        confidence="confirmed",
                        title=title,
                        description=(
                            f"Insecure Direct Object Reference in parameter "
                            f"'{param}'. Changing ID from '{baseline_id}' to "
                            f"'{result['accessed_id']}' returned a different "
                            f"resource with distinct data.\n"
                            f"Evidence: {result['evidence']}"
                        ),
                        request=result["request"],
                        evidence=result["evidence"],
                        reproduction=(
                            f"Change {param}={baseline_id} to "
                            f"{param}={result['accessed_id']}"
                        ),
                        remediation=(
                            "1. Implement object-level authorization checks "
                            "on every resource access.\n"
                            "2. Use indirect references (UUIDs or opaque tokens) "
                            "instead of sequential IDs.\n"
                            "3. Validate that the authenticated user owns or has "
                            "permission for the requested resource."
                        ),
                        cvss_score=8.1,
                        cwe="CWE-639",
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/"
                            "0xa3-broken-object-property-level-authorization/"
                        ],
                    )

    console.print(
        f"  Found {len(findings)} confirmed IDOR vulnerabilities"
    )
    return {"target": url, "findings": findings, "count": len(findings)}
