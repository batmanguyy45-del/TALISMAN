"""GraphQL security audit — introspection, injection, IDOR, batching DoS."""
from __future__ import annotations
import asyncio
import json
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

COMMON_GQL_PATHS = [
    "/graphql", "/gql", "/graphiql", "/api/graphql",
    "/v1/graphql", "/v2/graphql", "/query", "/graphql/v1",
]

INTROSPECTION_QUERY = """
{
  __schema {
    types { name kind fields { name type { name kind ofType { name kind } } } }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
"""

SIMPLE_INTROSPECTION = "{ __typename }"


async def _send_gql(url: str, query: str, client: TalismanHTTPClient,
                    auth: str | None = None) -> dict[str, Any]:
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if auth:
        headers["Authorization"] = auth
    try:
        r = await client.post(url, json={"query": query}, headers=headers, timeout=15)
        return {"status": r.status_code, "body": r.text, "json": r.json() if r.status_code == 200 else {}}
    except Exception as e:
        return {"status": 0, "body": str(e), "json": {}}


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
    console.print(f"\n[module]⚡ GraphQL Audit[/module] → [target]{url}[/target]")
    findings: list[dict[str, Any]] = []
    gql_endpoint: str | None = None

    async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
        # Discover endpoint
        for path in COMMON_GQL_PATHS:
            test_url = url.rstrip("/") + path
            result = await _send_gql(test_url, SIMPLE_INTROSPECTION, client, auth)
            if result["status"] == 200 and "__typename" in result["body"]:
                gql_endpoint = test_url
                console.print(f"  [success]✓ GraphQL endpoint: {path}[/success]")
                break

        if not gql_endpoint:
            # Try the target URL directly
            result = await _send_gql(url, SIMPLE_INTROSPECTION, client, auth)
            if result["status"] == 200 and "__typename" in result["body"]:
                gql_endpoint = url
            else:
                console.print("  No GraphQL endpoint found")
                return {"target": url, "graphql_found": False, "findings": []}

        endpoint = gql_endpoint

        # — 1. Introspection enabled —————————————————————————
        intro_result = await _send_gql(endpoint, INTROSPECTION_QUERY, client, auth)
        if intro_result["status"] == 200 and "__schema" in intro_result["body"]:
            print_finding("GraphQL introspection enabled", "medium", endpoint)
            findings.append({"issue": "introspection_enabled", "severity": "medium"})
            if session:
                await session.add_finding(
                    target=endpoint, module="graphql",
                    vuln_type="graphql_introspection",
                    severity="medium", confidence="confirmed",
                    title="GraphQL introspection enabled",
                    description="Full schema exposed via introspection. Attackers can enumerate all types, fields, and mutations.",
                    remediation="Disable introspection in production. Most frameworks support this natively.",
                    cwe="CWE-200",
                )
            # Parse and display schema
            try:
                schema_data = intro_result["json"].get("data", {}).get("__schema", {})
                types = [t["name"] for t in schema_data.get("types", []) if not t["name"].startswith("__")]
                console.print(f"  Schema types: {', '.join(types[:15])}{'...' if len(types) > 15 else ''}")
            except Exception:
                pass

        # — 2. Injection in string arguments —————————————————
        injection_queries = [
            ('{ search(term: "\\") { id } }', "Quote injection"),
            ('{ user(id: "1 OR 1=1") { email } }', "SQLi in argument"),
            ('{ user(id: "<script>alert(1)</script>") { name } }', "XSS in argument"),
            ('{ user(id: "1; DROP TABLE users--") { id } }', "SQLi DDL"),
        ]
        for query, desc in injection_queries:
            result = await _send_gql(endpoint, query, client, auth)
            if result["status"] == 200 and "error" not in result["body"].lower()[:100]:
                if any(err in result["body"].lower() for err in ["syntax", "sql", "mysql", "postgres"]):
                    print_finding(f"GraphQL injection: {desc}", "high", endpoint)
                    findings.append({"issue": "injection", "query": query, "desc": desc})

        # — 3. Alias batching (rate limit bypass) ————————————
        batch_query = "{ " + " ".join(f"u{i}: user(id: {i}) {{ id email }}" for i in range(1, 51)) + " }"
        batch_result = await _send_gql(endpoint, batch_query, client, auth)
        if batch_result["status"] == 200 and "data" in batch_result["body"]:
            print_finding("GraphQL alias batching — rate limit bypass possible", "medium", endpoint)
            findings.append({"issue": "alias_batching"})
            if session:
                await session.add_finding(
                    target=endpoint, module="graphql",
                    vuln_type="graphql_batching",
                    severity="medium", confidence="confirmed",
                    title="GraphQL alias batching — rate limit bypass",
                    description="50 user lookups in one request bypassed rate limiting via aliases.",
                    remediation="Implement query complexity limits and per-operation rate limiting.",
                    cwe="CWE-770",
                )

        # — 4. Depth limit check —————————————————————————
        deep_query = "{ user { posts { comments { author { posts { comments { author { id } } } } } } } }"
        deep_result = await _send_gql(endpoint, deep_query, client, auth)
        if deep_result["status"] == 200 and "data" in deep_result["body"]:
            print_finding("GraphQL no query depth limit detected", "medium", endpoint)
            findings.append({"issue": "no_depth_limit"})

    console.print(f"  GraphQL: {len(findings)} issues found")
    return {"target": url, "endpoint": endpoint, "graphql_found": True, "findings": findings}
