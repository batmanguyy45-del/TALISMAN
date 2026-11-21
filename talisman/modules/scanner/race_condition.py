"""Race-condition testing entry point.

A burst of successful HTTP responses is not evidence of a race condition.
Reliable race testing requires an application-specific operation, a controlled
test account/resource, a synchronization strategy, and a postcondition that
proves duplicate or inconsistent state. Generic parallel POST floods are
intentionally disabled.
"""
from __future__ import annotations

from typing import Any


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    parallel_count: int = 20,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    return {
        "target": url,
        "findings": [],
        "count": 0,
        "skipped": True,
        "reason": (
            "Generic concurrent requests are disabled because response "
            "successes and size differences do not establish a TOCTOU flaw "
            "and can trigger real transactions. Use an application-specific "
            "test with an authorized disposable resource and verified state "
            "invariant."
        ),
    }
