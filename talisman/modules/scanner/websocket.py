"""WebSocket assessment entry point.

The legacy implementation opened WebSocket connections through a separate
library, bypassing TALISMAN's destination IP pinning, shared concurrency and
proxy transport policy. It also sent generic injection strings and treated
reflected message content as vulnerabilities. Until a dedicated scoped
WebSocket transport is available, generic network probes are disabled.
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
            "endpoints": [],
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
            "endpoints": [],
            "findings": [],
            "candidates": [],
            "count": 0,
            "error": str(exc),
        }

    return {
        "target": url,
        "endpoints": [],
        "findings": [],
        "candidates": [],
        "count": 0,
        "skipped": True,
        "reason": (
            "WebSocket probing is temporarily disabled because the previous "
            "implementation bypassed TALISMAN's pinned HTTP transport and proxy "
            "policy. It also inferred injection from message reflection. A "
            "dedicated WebSocket transport with scope-aware DNS pinning, TLS/SNI, "
            "proxy support, bounded frames and browser-context verification is "
            "required before active WebSocket tests can run."
        ),
    }
