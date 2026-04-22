"""Business logic testing — price manipulation, workflow bypass, mass assignment."""
from __future__ import annotations
import asyncio
import json
import re
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

NEGATIVE_VALUE_PARAMS = ["price", "amount", "quantity", "qty", "total", "cost", "fee",
                          "discount", "credit", "points", "balance"]
MASS_ASSIGNMENT_FIELDS = ["role", "admin", "is_admin", "is_staff", "is_superuser",
                           "privilege", "level", "subscription", "plan", "verified",
                           "email_verified", "active", "status", "group", "permissions"]
WORKFLOW_CHECKOUT_PATHS = ["/checkout/confirm", "/order/complete", "/payment/confirm",
                            "/checkout/step3", "/checkout/final", "/cart/checkout"]


async def _test_negative_values(
    url: str, client: TalismanHTTPClient
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for param in NEGATIVE_VALUE_PARAMS:
        for value in ["-1", "-100", "-0.01", "0", "-9999"]:
            try:
                r = await client.post(url, json={param: value}, timeout=8)
                if r.status_code in (200, 201) and any(
                    kw in r.text.lower() for kw in ["success", "accepted", "created", "order"]
                ):
                    findings.append({
                        "issue": "negative_value_accepted",
                        "param": param,
                        "value": value,
                        "status": r.status_code,
                    })
            except Exception:
                pass
    return findings


async def _test_mass_assignment(
    url: str, client: TalismanHTTPClient
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        # Get baseline response structure
        r = await client.get(url, timeout=8)
        if r.status_code != 200:
            return findings
        # Try adding privileged fields to POST/PUT
        for field in MASS_ASSIGNMENT_FIELDS[:5]:
            try:
                r2 = await client.post(url, json={field: True, "admin": True}, timeout=8)
                if r2.status_code in (200, 201):
                    resp_json = {}
                    try:
                        resp_json = r2.json()
                    except Exception:
                        pass
                    if field in str(resp_json) and str(resp_json.get(field, "")).lower() in ("true", "1", "admin"):
                        findings.append({
                            "issue": "mass_assignment",
                            "field": field,
                            "accepted": True,
                            "response_snippet": str(resp_json)[:200],
                        })
            except Exception:
                pass
    except Exception:
        pass
    return findings


async def _test_workflow_skip(
    base_url: str, client: TalismanHTTPClient
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in WORKFLOW_CHECKOUT_PATHS:
        target_url = base_url.rstrip("/") + path
        try:
            r = await client.get(target_url, allow_redirects=False, timeout=8)
            if r.status_code == 200 and any(
                kw in r.text.lower() for kw in ["confirm", "order", "thank you", "success"]
            ):
                findings.append({
                    "issue": "workflow_skip",
                    "path": path,
                    "status": r.status_code,
                    "evidence": r.text[:200],
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
    url = target if "://" in target else f"https://{target}"
    console.print(f"\n[module]⚡ Business Logic Testing[/module] → [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:
        # Negative value injection
        neg_results = await _test_negative_values(url, client)
        for r in neg_results:
            title = f"Negative value accepted: {r['param']}={r['value']}"
            print_finding(title, "high", url)
            findings.append(r)
            if session:
                await session.add_finding(
                    target=url, module="business_logic",
                    vuln_type="negative_value_injection",
                    severity="high", confidence="likely",
                    title=title,
                    description=f"Parameter '{r['param']}' accepts negative value '{r['value']}', potentially causing financial calculation errors.",
                    remediation="Validate all numeric inputs server-side. Reject negative values for quantity/price fields.",
                    cwe="CWE-20",
                )

        # Mass assignment
        mass_results = await _test_mass_assignment(url, client)
        for r in mass_results:
            title = f"Mass assignment — field '{r['field']}' accepted and reflected"
            print_finding(title, "high", url)
            findings.append(r)
            if session:
                await session.add_finding(
                    target=url, module="business_logic",
                    vuln_type="mass_assignment",
                    severity="high", confidence="confirmed",
                    title=title,
                    description=f"Privileged field '{r['field']}' accepted in request body and reflected in response.",
                    remediation="Use allowlists (not denylists) for accepted request fields. Never bind user input directly to model properties.",
                    cvss_score=8.8, cwe="CWE-915",
                )

        # Workflow bypass
        workflow_results = await _test_workflow_skip(url, client)
        for r in workflow_results:
            title = f"Workflow bypass — direct access to {r['path']}"
            print_finding(title, "high", url)
            findings.append(r)
            if session:
                await session.add_finding(
                    target=url, module="business_logic",
                    vuln_type="workflow_bypass",
                    severity="high", confidence="likely",
                    title=title,
                    description=f"Checkout/confirmation step at {r['path']} accessible without completing prior steps.",
                    remediation="Validate session state at each workflow step. Enforce sequential completion server-side.",
                    cwe="CWE-284",
                )

    console.print(f"  Business logic testing complete — {len(findings)} issues")
    return {"target": url, "findings": findings, "count": len(findings)}
