"""Insecure-deserialization assessment entry point.

Generic probes for guessed endpoints are disabled. Sending native serialized
objects and gadget-shaped payloads to arbitrary application routes is unsafe,
and an HTTP 500 or echoed serialization signature does not prove that an
unsafe deserializer processed attacker-controlled data. Use an application-
specific disposable fixture with a safe inert marker and an independently
verified deserialization postcondition.
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
            "Generic deserialization probes are disabled. A server error or "
            "serialized signature reflection does not prove unsafe object "
            "deserialization. Use an application-specific disposable fixture "
            "with an inert marker and a verified postcondition."
        ),
    }
