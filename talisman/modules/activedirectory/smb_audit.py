"""SMB audit entry point.

The previous implementation used direct SMB connections and could enumerate
shares and retrieve sensitive SYSVOL/GPP content without applying the central
scope or rate policy. Generic SMB enumeration is disabled until the SMB
transport can enforce explicit host/IP scope and safe evidence handling.
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
        "shares": [],
        "sensitive_files": [],
        "gpp_credentials": [],
        "count": 0,
        "skipped": True,
        "reason": (
            "Generic SMB enumeration is disabled until direct SMB "
            "connections are scope-checked, pinned to an authorized IP, "
            "and sensitive file contents are handled safely."
        ),
    }
