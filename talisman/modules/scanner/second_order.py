"""Second-order testing entry point.

Generic endpoint guessing and mutation payloads are deliberately disabled.
A reliable assessment requires an operator-supplied disposable resource,
known store/trigger endpoints, and a verified cleanup/postcondition strategy.
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
            "skipped": True,
            "reason": "An explicit assessment scope is required.",
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
            "Generic second-order injection probes are disabled. "
            "The previous implementation guessed application endpoints and sent state-changing "
            "or potentially destructive payloads without a disposable test fixture or rollback. "
            "Use an application-specific test with an operator-supplied endpoint, disposable "
            "account/resource, minimal canary data, and verified cleanup."
        ),
    }
