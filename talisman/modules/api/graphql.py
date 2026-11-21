"""Passive GraphQL surface and schema-discovery assessment.

The former implementation sent guessed SQLi/XSS strings, large alias batches,
login mutations and guessed OTP values. Those requests could alter state or
lock accounts, and generic response acceptance does not prove an exploit.
This module now performs scoped, read-only GraphQL GET queries only.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import console, get_logger

log = get_logger(__name__)

COMMON_GQL_PATHS = [
    "/graphql",
    "/gql",
    "/graphiql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/graphql/v1",
]

INTROSPECTION_QUERY = """{
  __schema {
    types { name kind }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}"""

SIMPLE_INTROSPECTION = "{ __typename }"


async def _query_graphql(
    url: str,
    query: str,
    client: TalismanHTTPClient,
    auth: str | None = None,
) -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    if auth:
        headers["Authorization"] = auth
    try:
        response = await client.get(
            url,
            params={"query": query},
            headers=headers,
            timeout=12,
        )
        try:
            data = response.json()
        except ValueError:
            data = {}
        return {
            "status": response.status_code,
            "body": response.text[:200_000],
            "json": data if isinstance(data, dict) else {},
        }
    except Exception as exc:
        log.debug("graphql_read_only_query_failed", error=type(exc).__name__)
        return {"status": 0, "body": "", "json": {}}


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
    if scope is None:
        return {
            "target": url,
            "graphql_found": False,
            "findings": [],
            "observations": [],
            "count": 0,
            "error": "scope_enforcer_required",
        }

    try:
        scope.assert_in_scope(url)
    except ScopeViolationError as exc:
        return {
            "target": url,
            "graphql_found": False,
            "findings": [],
            "observations": [],
            "count": 0,
            "error": str(exc),
        }

    console.print(
        f"\\n[module][+] Passive GraphQL Discovery[/module] -> [target]{url}[/target]"
    )
    endpoint: str | None = None
    observations: list[dict[str, Any]] = []

    async with TalismanHTTPClient(
        proxy=proxy,
        timeout=15,
        verify_ssl=True,
        follow_redirects=False,
        scope=scope,
    ) as client:
        candidates = [url.rstrip("/") + path for path in COMMON_GQL_PATHS]
        candidates.append(url)

        for candidate in candidates:
            result = await _query_graphql(
                candidate,
                SIMPLE_INTROSPECTION,
                client,
                auth,
            )
            body = result["body"]
            if result["status"] == 200 and (
                "__typename" in body or "data" in result["json"]
            ):
                endpoint = candidate
                break

        if endpoint:
            schema_result = await _query_graphql(
                endpoint,
                INTROSPECTION_QUERY,
                client,
                auth,
            )
            schema = (
                schema_result["json"].get("data", {}).get("__schema")
                if isinstance(schema_result["json"].get("data"), dict)
                else None
            )
            if schema_result["status"] == 200 and isinstance(schema, dict):
                types = [
                    item.get("name", "")
                    for item in schema.get("types", [])
                    if isinstance(item, dict)
                    and isinstance(item.get("name"), str)
                    and not item["name"].startswith("__")
                ]
                observations.append({
                    "type": "graphql_introspection_enabled",
                    "endpoint": urlsplit(endpoint).path or "/",
                    "schema_type_count": len(types),
                    "schema_type_names": types[:50],
                    "classification": "api_surface_observation",
                    "note": (
                        "Introspection availability reveals schema metadata but "
                        "does not establish unauthorized access to protected data "
                        "or mutations."
                    ),
                })
            elif schema_result["status"] in {401, 403}:
                observations.append({
                    "type": "graphql_introspection_restricted",
                    "endpoint": urlsplit(endpoint).path or "/",
                    "status": schema_result["status"],
                    "classification": "api_surface_observation",
                })

    console.print(
        f" GraphQL discovery complete — {'endpoint found' if endpoint else 'no endpoint found'}; "
        f"{len(observations)} schema observations; no mutations or batching probes sent"
    )
    return {
        "target": url,
        "endpoint": endpoint,
        "graphql_found": endpoint is not None,
        "findings": [],
        "observations": observations,
        "count": 0,
        "observation_count": len(observations),
        "state_changing_probes_sent": 0,
    }
