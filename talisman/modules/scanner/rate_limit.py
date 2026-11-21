"""Rate-limit assessment using an operator-supplied disposable test fixture.

The generic implementation previously guessed login/OTP/password-reset routes and
sent bursts of requests. That could lock real accounts or trigger email/OTP
side effects. This implementation sends no traffic unless the operator supplies
a disposable endpoint and bounded test payload explicitly.
"""
from __future__ import annotations

import time
from typing import Any
from urllib.parse import urljoin, urlsplit

from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import console, get_logger

log = get_logger(__name__)

MAX_FIXTURE_ATTEMPTS = 10


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    test_fixture: dict[str, Any] | None = None,
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

    if not isinstance(test_fixture, dict):
        return {
            "target": url,
            "findings": [],
            "candidates": [],
            "count": 0,
            "skipped": True,
            "reason": (
                "Generic rate-limit bursts against guessed authentication, OTP and "
                "password-reset endpoints are disabled. Supply test_fixture with "
                "an in-scope endpoint, method, disposable test payload and 2-10 "
                "attempts. Use an account that can safely tolerate failed attempts."
            ),
        }

    endpoint = test_fixture.get("endpoint")
    method = str(test_fixture.get("method", "POST")).upper()
    payload = test_fixture.get("payload")
    attempts = test_fixture.get("attempts", 5)

    if not isinstance(endpoint, str) or not endpoint.strip():
        return {"target": url, "findings": [], "count": 0, "error": "test_fixture.endpoint_required"}
    if method not in {"GET", "POST"}:
        return {
            "target": url,
            "findings": [],
            "count": 0,
            "error": "test_fixture.method_must_be_GET_or_POST",
        }
    if not isinstance(payload, dict):
        return {
            "target": url,
            "findings": [],
            "count": 0,
            "error": "test_fixture.payload_must_be_a_mapping",
        }
    if (
        isinstance(attempts, bool)
        or not isinstance(attempts, int)
        or not 2 <= attempts <= MAX_FIXTURE_ATTEMPTS
    ):
        return {
            "target": url,
            "findings": [],
            "count": 0,
            "error": f"test_fixture.attempts_must_be_between_2_and_{MAX_FIXTURE_ATTEMPTS}",
        }

    test_url = urljoin(url.rstrip("/") + "/", endpoint.lstrip("/"))
    try:
        scope.assert_in_scope(test_url)
        if method == "POST":
            scope.assert_destructive_allowed(test_url, method)
    except ScopeViolationError as exc:
        return {
            "target": url,
            "findings": [],
            "candidates": [],
            "count": 0,
            "skipped": True,
            "reason": str(exc),
        }

    statuses: list[int] = []
    retry_after_values: list[str] = []
    rate_limit_headers_seen: set[str] = set()
    elapsed_seconds: list[float] = []

    console.print(
        f"\\n[module][+] Controlled Rate-Limit Assessment[/module] -> [target]{test_url}[/target]"
    )
    async with TalismanHTTPClient(
        proxy=proxy,
        timeout=10,
        verify_ssl=True,
        follow_redirects=False,
        scope=scope,
    ) as client:
        for _ in range(attempts):
            started = time.monotonic()
            try:
                if method == "GET":
                    response = await client.get(test_url, params=payload, timeout=8)
                else:
                    response = await client.post(test_url, json=payload, timeout=8)
                elapsed_seconds.append(round(time.monotonic() - started, 3))
                statuses.append(response.status_code)
                if response.headers.get("retry-after"):
                    retry_after_values.append(response.headers["retry-after"][:80])
                for header in (
                    "ratelimit-limit",
                    "ratelimit-remaining",
                    "ratelimit-reset",
                    "x-ratelimit-limit",
                    "x-ratelimit-remaining",
                    "x-ratelimit-reset",
                ):
                    if response.headers.get(header) is not None:
                        rate_limit_headers_seen.add(header)
            except Exception as exc:
                elapsed_seconds.append(round(time.monotonic() - started, 3))
                statuses.append(0)
                log.debug("rate_limit_fixture_request_failed", error=type(exc).__name__)

    throttled = any(status in {429, 503} for status in statuses)
    candidate: list[dict[str, Any]] = []
    observations = [{
        "type": "bounded_rate_limit_test",
        "endpoint": urlsplit(test_url).path,
        "method": method,
        "attempts": attempts,
        "statuses": statuses,
        "retry_after_observed": bool(retry_after_values),
        "rate_limit_headers_observed": sorted(rate_limit_headers_seen),
        "elapsed_seconds": elapsed_seconds,
        "classification": "controlled_test_observation",
        "note": (
            "Requests were serial and capped by the assessment's shared rate "
            "limiter. The result describes only this test window and account; "
            "it does not prove system-wide absence or presence of rate limiting."
        ),
    }]

    if not throttled and not retry_after_values and not rate_limit_headers_seen:
        candidate.append({
            "type": "rate_limit_not_observed_in_bounded_sample",
            "confidence": "candidate",
            "endpoint": urlsplit(test_url).path,
            "method": method,
            "attempts": attempts,
            "statuses": statuses,
            "requires_threshold_validation": True,
            "verification_required": (
                "Repeat on the disposable account across an authorized threshold "
                "window, inspect account/IP/session counters and Retry-After "
                "behavior, and ensure lockout or secondary controls were not "
                "mistaken for the rate limiter."
            ),
        })

    return {
        "target": url,
        "findings": [],
        "candidates": candidate,
        "observations": observations,
        "count": 0,
        "candidate_count": len(candidate),
        "observation_count": len(observations),
        "test_fixture_used": True,
    }
