"""Server-side prototype-pollution scanner (currently disabled).

The previous generic checks sent persistent prototype-mutation payloads to
arbitrary JSON endpoints and inferred a critical vulnerability from response
formatting or status differences. Those observations do not prove prototype
pollution and the requests can mutate live application state. The generic
scanner is therefore disabled until an application-specific, disposable test
fixture and an independently verifiable global-state postcondition exist.
"""
from __future__ import annotations

from typing import Any

SSPP_CANARY_PREFIX = "TLSMSSPP"
JSON_ENDPOINTS = [
    "/api/user",
    "/api/users",
    "/api/profile",
    "/api/v1/user",
    "/api/v1/users",
    "/api/v1/profile",
    "/api/data",
    "/api/config",
    "/api/settings",
    "/api/status",
    "/api/health",
    "/api/login",
    "/api/auth",
]


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    return {
        "target": url,
        "findings": [],
        "count": 0,
        "skipped": True,
        "reason": (
            "Generic prototype-pollution probes are disabled. They previously "
            "sent persistent __proto__/constructor mutations and promoted "
            "response-format changes to critical findings without proving "
            "global prototype modification. Use an application-specific "
            "disposable fixture with a verified postcondition."
        ),
    }
