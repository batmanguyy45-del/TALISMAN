"""Passive OAuth 2.0 / OpenID Connect discovery and posture assessment.

OAuth token exchanges and authorization-flow mutation tests are not run
automatically. They require a registered disposable client, a controlled
redirect URI, a dedicated test identity and explicit active-test authorization.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import console, get_logger

log = get_logger(__name__)

OAUTH_DISCOVERY_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/.well-known/openid-configuration",
    "/auth/realms/master/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server/",
]


async def _discover_oauth(
    base_url: str,
    client: TalismanHTTPClient,
) -> dict[str, Any] | None:
    for path in OAUTH_DISCOVERY_PATHS:
        try:
            response = await client.get(
                base_url.rstrip("/") + path,
                timeout=8,
            )
            if response.status_code != 200:
                continue
            data = response.json()
            if (
                isinstance(data, dict)
                and (
                    isinstance(data.get("authorization_endpoint"), str)
                    or isinstance(data.get("token_endpoint"), str)
                )
            ):
                return data
        except Exception as exc:
            log.debug("oauth_discovery_failed", error=type(exc).__name__)
    return None


def _endpoint_summary(
    value: Any,
    scope: Any,
) -> dict[str, Any] | None:
    if not isinstance(value, str):
        return None
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return {"valid_url": False, "in_scope": False}
    return {
        "scheme": parsed.scheme,
        "host": parsed.hostname,
        "path": parsed.path or "/",
        "in_scope": scope.is_in_scope(value) or scope.is_service_allowed(value),
    }


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    client_id: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    if scope is None:
        return {
            "target": url,
            "oauth_config": None,
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
            "oauth_config": None,
            "findings": [],
            "observations": [],
            "count": 0,
            "error": str(exc),
        }

    console.print(
        f"\\n[module][+] Passive OAuth/OIDC Discovery[/module] -> [target]{url}[/target]"
    )
    async with TalismanHTTPClient(
        proxy=proxy,
        timeout=12,
        verify_ssl=True,
        follow_redirects=False,
        scope=scope,
    ) as client:
        config = await _discover_oauth(url, client)

    if not config:
        return {
            "target": url,
            "oauth_config": None,
            "findings": [],
            "observations": [],
            "count": 0,
            "oauth_found": False,
            "active_tests_performed": False,
        }

    observations: list[dict[str, Any]] = []
    response_types = config.get("response_types_supported", [])
    if isinstance(response_types, list) and "token" in response_types:
        observations.append({
            "type": "implicit_response_type_advertised",
            "classification": "oauth_posture_observation",
            "severity_hint": "medium",
            "note": (
                "The discovery document advertises the implicit response type. "
                "Verify whether the authorization server actually permits it for "
                "the relevant client and whether tokens are returned in a browser URL."
            ),
        })

    pkce_methods = config.get("code_challenge_methods_supported", [])
    if not isinstance(pkce_methods, list) or "S256" not in pkce_methods:
        observations.append({
            "type": "pkce_s256_not_advertised",
            "classification": "oauth_posture_observation",
            "severity_hint": "medium",
            "note": (
                "The discovery metadata does not advertise S256 PKCE. This alone "
                "does not prove the server accepts authorization requests without "
                "PKCE or permits a downgrade."
            ),
        })

    endpoint_summaries: dict[str, Any] = {}
    for field in (
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "revocation_endpoint",
        "introspection_endpoint",
        "jwks_uri",
    ):
        summary = _endpoint_summary(config.get(field), scope)
        if summary is not None:
            endpoint_summaries[field] = summary
            if summary.get("valid_url") is False or summary.get("in_scope") is False:
                observations.append({
                    "type": "advertised_endpoint_outside_scope",
                    "field": field,
                    "host": summary.get("host"),
                    "classification": "scope_observation",
                    "note": (
                        "The endpoint was listed in discovery metadata but was not "
                        "requested because it is outside the explicit assessment scope."
                    ),
                })

    safe_config = {
        "issuer": config.get("issuer"),
        "scopes_supported": config.get("scopes_supported", []),
        "response_types_supported": response_types if isinstance(response_types, list) else [],
        "grant_types_supported": (
            config.get("grant_types_supported", [])
            if isinstance(config.get("grant_types_supported", []), list)
            else []
        ),
        "code_challenge_methods_supported": (
            pkce_methods if isinstance(pkce_methods, list) else []
        ),
        "endpoints": endpoint_summaries,
    }

    console.print(
        f" OAuth/OIDC discovery complete — {len(observations)} posture observations; "
        "no authorization codes, tokens or credentials were submitted"
    )
    return {
        "target": url,
        "oauth_config": safe_config,
        "findings": [],
        "observations": observations,
        "count": 0,
        "observation_count": len(observations),
        "oauth_found": True,
        "active_tests_performed": False,
        "active_tests_skipped": bool(client_id),
        "active_test_requirement": (
            "Use a registered disposable client, dedicated test identity, controlled "
            "redirect URI and explicit active-test authorization before evaluating "
            "state, PKCE, redirect validation or code replay."
        ),
    }
