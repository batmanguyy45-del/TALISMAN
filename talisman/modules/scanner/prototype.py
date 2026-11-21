"""Prototype-pollution assessment entry point.

Generic query/JSON prototype mutation is disabled. A canary reflected in an
HTTP response does not prove a JavaScript object prototype was modified, and
persistent prototype mutations can corrupt live application state. A valid
assessment requires an operator-supplied disposable endpoint and a server- or
browser-side postcondition that proves prototype mutation.
"""
from __future__ import annotations

from typing import Any

from talisman.engine.scope import ScopeViolationError


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
    except ScopeViolationError as exc:
        return {
            "target": url,
            "findings": [],
            "candidates": [],
            "count": 0,
            "error": str(exc),
        }

    return {
        "target": url,
        "findings": [],
        "candidates": [],
        "count": 0,
        "skipped": True,
        "reason": (
            "Generic prototype-pollution probes are disabled. Reflection of "
            "__proto__/constructor canaries is not proof of prototype mutation. "
            "Use an application-specific disposable fixture and verify a "
            "server-side or browser-side global prototype postcondition."
        ),
    }
