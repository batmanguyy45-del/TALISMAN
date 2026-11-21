"""Web cache deception scanner — static path confusion, session/JWT leakage via cache."""
from __future__ import annotations
import asyncio
import random
import string
from typing import Any
from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.redaction import redact_sensitive_text
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

STATIC_EXTENSIONS = [".css", ".js", ".ico", ".png", ".jpg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".eot"]
DYNAMIC_PATHS = [
    "/profile", "/api/user", "/api/users/me",
    "/account", "/settings",
    "/dashboard", "/api/dashboard",
    "/orders", "/api/orders",
    "/messages", "/api/messages",
]


async def _test_cache_deception(
    url: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test web cache deception by appending static extensions to dynamic paths."""
    findings: list[dict[str, Any]] = []
    nonce = ''.join(random.choices(string.ascii_lowercase, k=6))

    for dynamic_path in DYNAMIC_PATHS:
        for ext in STATIC_EXTENSIONS[:4]:  # Test the most common extensions
            # Append static extension to the dynamic path
            deceptive_path = f"{dynamic_path}/{nonce}{ext}"
            test_url = url.rstrip("/") + deceptive_path

            try:
                r = await client.get(
                    test_url,
                    headers={"Cache-Control": "no-cache", "Pragma": "no-cache"},
                    timeout=8,
                )

                # Check if the response is cacheable
                cache_control = (r.headers.get("cache-control", "") or "").lower()
                content_type = (r.headers.get("content-type", "") or "").lower()
                set_cookie = r.headers.get("set-cookie", "")

                is_cacheable = (
                    "public" in cache_control
                    or "max-age" in cache_control
                    or r.status_code in (200, 203, 204, 206, 300, 301, 404, 410)
                )

                if is_cacheable:
                    # Check if sensitive content is served with the cached response
                    has_sensitive = (
                        "profile" in r.text.lower()
                        or "email" in r.text.lower()
                        or "session" in r.text.lower()
                        or "token" in r.text.lower()
                        or "api" in r.text.lower()
                    )

                    if has_sensitive and (not set_cookie or "samesite" not in set_cookie.lower()):
                        findings.append({
                            "path": deceptive_path,
                            "extension": ext,
                            "status": r.status_code,
                            "content_type": content_type,
                            "cache_control": cache_control,
                            "has_set_cookie": bool(set_cookie),
                            "response_preview": r.text[:300],
                            "issue": "cacheable_dynamic_response",
                        })

                # Check for different response when requesting with static extension
                # vs without
                normal_url = url.rstrip("/") + dynamic_path
                try:
                    r2 = await client.get(
                        normal_url,
                        headers={"Cache-Control": "no-cache"},
                        timeout=8,
                    )
                    if r.status_code == r2.status_code and len(r.text) > 0:
                        # Same response — CDN is serving dynamic content as static
                        findings.append({
                            "path": deceptive_path,
                            "extension": ext,
                            "issue": "path_confusion",
                            "evidence": "Dynamic path and static-extension path return identical content",
                        })
                        break
                except Exception:
                    pass

            except Exception:
                pass

        if any(f.get("issue") in ("path_confusion",) for f in findings):
            break

    return findings


async def _test_cache_key_confusion(
    url: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test if cache keys ignore certain parameters, allowing cache poisoning."""
    findings: list[dict[str, Any]] = []
    canary = f"TLSMCACHE{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"
    param_name = f"cb_{''.join(random.choices(string.ascii_lowercase, k=4))}"

    # Request 1: with a unique parameter
    try:
        r1 = await client.get(url, params={param_name: canary}, timeout=8)
        body1 = r1.text
    except Exception:
        return findings

    # Request 2: without the parameter (should hit same cache if key ignores it)
    try:
        r2 = await client.get(url, timeout=8)
        body2 = r2.text
    except Exception:
        return findings

    # If different parameters produce same response, cache key is parameter-agnostic
    if body1 == body2 and len(body1) > 100:
        findings.append({
            "issue": "cache_key_confusion",
            "description": f"Parameter '{param_name}' is ignored in cache key",
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
    if scope is None:
        return {
            "target": url,
            "findings": [],
            "candidates": [],
            "count": 0,
            "error": "scope_enforcer_required",
        }
    try:
        scope.assert_in_scope(url)
        # These requests deliberately vary cache paths and may populate a
        # shared cache, so they are not part of the default read-only profile.
        scope.assert_destructive_allowed(url, "GET")
    except ScopeViolationError as exc:
        return {
            "target": url,
            "findings": [],
            "candidates": [],
            "count": 0,
            "skipped": True,
            "reason": str(exc),
        }

    candidates: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    console.print(
        f"\\n[module][+] Web Cache Deception Assessment[/module] -> [target]{url}[/target]"
    )

    async with TalismanHTTPClient(
        proxy=proxy,
        timeout=12,
        verify_ssl=True,
        follow_redirects=False,
        scope=scope,
    ) as client:
        deception_results = await _test_cache_deception(url, client)
        key_results = await _test_cache_key_confusion(url, client)

    for result in deception_results:
        safe_result = dict(result)
        if isinstance(safe_result.get("response_preview"), str):
            safe_result["response_preview"] = redact_sensitive_text(
                safe_result["response_preview"]
            )
        candidates.append({
            **safe_result,
            "confidence": "candidate",
            "requires_cross_user_cache_validation": True,
            "verification_required": (
                "Confirm the response contains non-public data from an authenticated "
                "test account, that a cache actually stored it, and that a second "
                "independent unauthenticated or different-user client receives it. "
                "Identical status/body or a cache-control header alone does not "
                "prove cache deception."
            ),
        })

    for result in key_results:
        observations.append({
            **result,
            "classification": "cache_behavior_observation",
            "note": (
                "Identical responses for URLs with and without a parameter may be "
                "normal application behavior and do not prove a shared cache key."
            ),
        })

    console.print(
        f" Cache deception assessment complete — {len(candidates)} cross-user "
        f"exposure candidates, {len(observations)} cache behavior observations"
    )
    return {
        "target": url,
        "findings": [],
        "candidates": candidates,
        "observations": observations,
        "count": 0,
        "candidate_count": len(candidates),
        "observation_count": len(observations),
        "destructive_probe_opt_in_required": True,
    }
