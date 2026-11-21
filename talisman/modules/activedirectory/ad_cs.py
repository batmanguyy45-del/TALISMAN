"""Active Directory Certificate Services audit is disabled pending safe LDAP transport.

The legacy implementation used direct LDAP connections without destination pinning
or a StartTLS/LDAPS requirement, and embedded the supplied password in finding
reproduction text. This entry point intentionally performs no network activity.
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
            "count": 0,
            "error": "scope_enforcer_required",
        }

    return {
        "target": target,
        "findings": [],
        "count": 0,
        "skipped": True,
        "reason": (
            "AD CS enumeration is disabled until LDAP is pinned to a validated "
            "in-scope IP, encrypted with verified LDAPS/StartTLS, and credentials "
            "are kept out of logs, findings, and reproduction steps. No network "
            "requests were sent and supplied credentials were not accessed."
        ),
    }
