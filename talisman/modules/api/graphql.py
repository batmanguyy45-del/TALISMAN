"""GraphQL security audit — introspection, injection, IDOR, batching DoS, array batching, mutation batching, query cost analysis."""
from __future__ import annotations
import asyncio
import json
import random
import string
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


async def _send_gql_raw(url: str, payload: dict, client: TalismanHTTPClient,
                         auth: str | None = None) -> dict[str, Any]:
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if auth:
        headers["Authorization"] = auth
    try:
        r = await client.post(url, json=payload, headers=headers, timeout=15)
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
    console.print(f"\n[module][+] GraphQL Audit[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []
    gql_endpoint: str | None = None

    async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
        # Discover endpoint
        for path in COMMON_GQL_PATHS:
            test_url = url.rstrip("/") + path
            result = await _send_gql(test_url, SIMPLE_INTROSPECTION, client, auth)
            if result["status"] == 200 and "__typename" in result["body"]:
                gql_endpoint = test_url
                console.print(f" [success][+] GraphQL endpoint: {path}[/success]")
                break

        if not gql_endpoint:
            result = await _send_gql(url, SIMPLE_INTROSPECTION, client, auth)
            if result["status"] == 200 and "__typename" in result["body"]:
                gql_endpoint = url
            else:
                console.print(" No GraphQL endpoint found")
                return {"target": url, "graphql_found": False, "findings": []}

        endpoint = gql_endpoint

        # -- 1. Introspection enabled -------------------------------------------------
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
            try:
                schema_data = intro_result["json"].get("data", {}).get("__schema", {})
                types = [t["name"] for t in schema_data.get("types", []) if not t["name"].startswith("__")]
                console.print(f" Schema types: {', '.join(types[:15])}{'...' if len(types) > 15 else ''}")
            except Exception:
                pass

        # -- 2. Injection in string arguments -----------------------------------------
        injection_queries = [
            ('{ search(term: "\\\\") { id } }', "Quote injection"),
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

        # -- 3. Alias batching (rate limit bypass) ------------------------------------
        batch_query = "{ " + " ".join(f"u{i}: user(id: {i}) {{ id email }}" for i in range(1, 51)) + " }"
        batch_result = await _send_gql(endpoint, batch_query, client, auth)
        if batch_result["status"] == 200 and "data" in batch_result["body"]:
            print_finding("GraphQL alias batching -- rate limit bypass possible", "medium", endpoint)
            findings.append({"issue": "alias_batching"})
            if session:
                await session.add_finding(
                    target=endpoint, module="graphql",
                    vuln_type="graphql_batching",
                    severity="medium", confidence="confirmed",
                    title="GraphQL alias batching -- rate limit bypass",
                    description="50 user lookups in one request bypassed rate limiting via aliases.",
                    remediation="Implement query complexity limits and per-operation rate limiting.",
                    cwe="CWE-770",
                )

        # -- 4. Array batching (batch query array) ------------------------------------
        array_batch = [{"query": "{ __typename }"} for _ in range(20)]
        array_result = await _send_gql_raw(endpoint, array_batch, client, auth)
        if array_result["status"] == 200:
            resp_text = array_result["body"]
            # Count how many __typename responses came back
            typename_count = resp_text.count("__typename")
            if typename_count >= 10:
                print_finding(f"GraphQL array batching accepted -- {typename_count} responses in one request", "medium", endpoint)
                findings.append({"issue": "array_batching", "count": typename_count})
                if session:
                    await session.add_finding(
                        target=endpoint, module="graphql",
                        vuln_type="graphql_array_batching",
                        severity="medium", confidence="confirmed",
                        title=f"GraphQL array batching -- {typename_count} operations in one request",
                        description="Server accepted a JSON array of GraphQL operations. Allows batching many queries/mutations in a single HTTP request, bypassing per-request rate limits.",
                        remediation="Disable array-based batching if not required, or apply per-operation rate limits and complexity scoring.",
                        cwe="CWE-770",
                    )

        # -- 5. Mutation alias batching (auth bypass) ---------------------------------
        rand_suffix = ''.join(random.choices(string.ascii_lowercase, k=4))
        mutation_aliases = " ".join(
            f'a{i}: login(username: "admin", password: "wrong{i}{rand_suffix}") {{ success token }}'
            for i in range(20)
        )
        mutation_batch = f"mutation {{ {mutation_aliases} }}"
        mut_result = await _send_gql(endpoint, mutation_batch, client, auth)
        if mut_result["status"] == 200:
            resp_lower = mut_result["body"].lower()
            # If we get any data back (even errors per-alias), it accepted the mutation batch
            if '"data"' in resp_lower or "success" in resp_lower:
                print_finding("GraphQL mutation alias batching accepted -- parallel auth attempts possible", "high", endpoint)
                findings.append({"issue": "mutation_alias_batching"})
                if session:
                    await session.add_finding(
                        target=endpoint, module="graphql",
                        vuln_type="graphql_mutation_batching",
                        severity="high", confidence="confirmed",
                        title="GraphQL mutation alias batching -- parallel authentication attempts",
                        description="Server accepted 20 parallel login mutations in a single request via aliases. This enables brute-force attacks against authentication and OTP endpoints without triggering per-request rate limits.",
                        remediation="1. Enforce per-operation rate limits that count each aliased operation separately. 2. Use query complexity scoring. 3. Consider disabling aliases on mutation endpoints.",
                        cwe="CWE-770",
                    )

        # -- 6. OTP alias brute force -------------------------------------------------
        rand_suffix2 = ''.join(random.choices(string.ascii_lowercase, k=4))
        otp_aliases = " ".join(
            f'b{i}: verifyOTP(otp: "{str(i).zfill(6)}", user: "admin") {{ success token }}'
            for i in range(20)
        )
        otp_batch = f"mutation {{ {otp_aliases} }}"
        otp_result = await _send_gql(endpoint, otp_batch, client, auth)
        if otp_result["status"] == 200 and '"data"' in otp_result["body"].lower():
            print_finding("GraphQL OTP alias batching -- parallel OTP brute force possible", "high", endpoint)
            findings.append({"issue": "otp_alias_batching"})
            if session:
                await session.add_finding(
                    target=endpoint, module="graphql",
                    vuln_type="graphql_otp_batching",
                    severity="high", confidence="confirmed",
                    title="GraphQL OTP alias batching -- parallel OTP brute force",
                    description="Server accepted 20 parallel OTP verification mutations via aliases. Attackers can brute-force OTP codes without triggering per-request rate limits.",
                    remediation="1. Rate limit OTP verification per session, not per request. 2. Implement lockout after failed attempts. 3. Use short TTL for OTP codes.",
                    cwe="CWE-770",
                )

        # -- 7. Depth limit check ----------------------------------------------------
        deep_query = "{ user { posts { comments { author { posts { comments { author { id } } } } } } } }"
        deep_result = await _send_gql(endpoint, deep_query, client, auth)
        if deep_result["status"] == 200 and "data" in deep_result["body"]:
            print_finding("GraphQL no query depth limit detected", "medium", endpoint)
            findings.append({"issue": "no_depth_limit"})
            if session:
                await session.add_finding(
                    target=endpoint, module="graphql",
                    vuln_type="graphql_no_depth_limit",
                    severity="medium", confidence="confirmed",
                    title="GraphQL no query depth limit detected",
                    description="7-level deep nested query was accepted. Attackers can craft deeply nested queries to cause CPU exhaustion.",
                    remediation="Implement query depth limiting. Typical limits are 5-7 levels.",
                    cwe="CWE-770",
                )

        # -- 8. Query cost analysis --------------------------------------------------
        cost_queries = [
            ("{ allUsers { id name email posts { title comments { body } } } }", "High-cost list query"),
            ("{ " + " ".join(f"f{i}: __typename" for i in range(100)) + " }", "High-breadth query (100 fields)"),
        ]
        for cost_query, cost_desc in cost_queries:
            cost_result = await _send_gql(endpoint, cost_query, client, auth)
            if cost_result["status"] == 200:
                resp_text = cost_result["body"]
                resource_indicators = ["error", "timeout", "too complex", "exceeded", "limit"]
                if not any(ind in resp_text.lower()[:500] for ind in resource_indicators):
                    print_finding(f"GraphQL cost analysis: {cost_desc} accepted", "low", endpoint)
                    findings.append({"issue": "high_cost_query_accepted", "desc": cost_desc})

    console.print(f" GraphQL: {len(findings)} issues found")
    return {"target": url, "endpoint": endpoint, "graphql_found": True, "findings": findings}
