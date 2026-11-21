"""NoSQL injection assessment entry point.

The previous scanner guessed login/API endpoints, sent authentication-bypass
operators and classified generic success words (including "token" and
"session") as confirmed injection. That is not defensible evidence and can
alter application state. A reliable NoSQLi test requires an operator-supplied
disposable endpoint, known request schema and a reproducible true/false
query oracle.
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
            "Generic NoSQLi endpoint guessing and authentication-bypass payloads "
            "are disabled. A 200 response or the presence of 'success', 'token' "
            "or 'session' is not proof of query injection. Supply an "
            "application-specific disposable endpoint and verify a deterministic "
            "true/false query result before reporting."
        ),
    }
