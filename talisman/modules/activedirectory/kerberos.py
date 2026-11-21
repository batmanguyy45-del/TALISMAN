"""Kerberos audit entry point.

The former implementation placed domain credentials in process arguments and
wrote ticket material to a predictable /tmp path. It also performed active
credential-enumeration attacks without enforcing target scope. That path is
disabled until a safe Impacket API implementation, private evidence storage,
and explicit domain-controller scope enforcement are available.
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
        "hashes": [],
        "count": 0,
        "skipped": True,
        "reason": (
            "Kerberos ticket-enumeration is disabled in this build. The prior "
            "implementation exposed credentials in process arguments and used "
            "predictable temporary-file storage."
        ),
    }
