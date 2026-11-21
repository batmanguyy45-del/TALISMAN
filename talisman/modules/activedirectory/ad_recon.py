"""Active Directory discovery entry point.

The previous LDAP enumeration helper connected directly to a supplied host
without using the assessment scope or shared rate policy. This generic
implementation is disabled until the LDAP transport can pin a validated
destination IP and enforce explicit domain scope.
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
    return {
        "target": target,
        "users": [],
        "groups": [],
        "computers": [],
        "spn_users": [],
        "asrep_users": [],
        "admins": [],
        "count": 0,
        "skipped": True,
        "reason": (
            "Generic LDAP enumeration is disabled until its direct network "
            "transport enforces the same scope and destination pinning as "
            "the shared HTTP client."
        ),
    }
