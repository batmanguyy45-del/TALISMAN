"""Active Directory password spraying is disabled pending safe transport and evidence handling.

The legacy implementation used direct LDAP connections without address pinning,
implemented a shorter-than-documented inter-round delay, and could expose cleartext
passwords in console output, result objects, and persisted reproduction data.
"""
from __future__ import annotations

from typing import Any


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    if scope is None:
        return {
            "target": target,
            "findings": [],
            "hits": [],
            "count": 0,
            "error": "scope_enforcer_required",
        }

    return {
        "target": target,
        "findings": [],
        "hits": [],
        "count": 0,
        "skipped": True,
        "reason": (
            "AD password spraying is disabled. The previous implementation "
            "used unpinned LDAP transport, did not honor its advertised lockout "
            "delay, and could expose supplied passwords in output and reports. "
            "No usernames or passwords were read, logged, persisted, or sent."
        ),
    }
