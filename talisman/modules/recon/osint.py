"""Scoped passive OSINT observations for an authorized target domain.

This module reports references and observations only. Finding an email address
or a paste mentioning a company is not, by itself, a vulnerability. S3 bucket
name guessing is deliberately excluded because it probes third-party resources
that are not proven to be owned by the target.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import console, get_logger

log = get_logger(__name__)


async def _harvest_emails(
    domain: str,
    client: TalismanHTTPClient,
    page_url: str,
) -> list[str]:
    emails: set[str] = set()
    email_re = re.compile(
        rf"[a-zA-Z0-9._%+\-]+@{re.escape(domain)}",
        re.IGNORECASE,
    )

    provider_url = (
        "https://api.hackertarget.com/emailfinder/"
        f"?q={domain}"
    )
    try:
        response = await client.get(provider_url, timeout=10)
        if response.status_code == 200:
            emails.update(email_re.findall(response.text))
    except Exception as exc:
        log.debug("email_provider_error", error=type(exc).__name__)

    try:
        response = await client.get(page_url, timeout=10)
        if response.status_code == 200:
            emails.update(email_re.findall(response.text))
    except Exception as exc:
        log.debug("email_page_error", error=type(exc).__name__)

    return sorted(emails)


async def _check_pastebin(
    domain: str,
    client: TalismanHTTPClient,
) -> list[dict[str, str]]:
    """Retrieve public paste references; do not fetch or expose paste contents."""
    try:
        response = await client.get(
            f"https://psbdmp.ws/api/v3/search/{domain}",
            timeout=10,
        )
        if response.status_code != 200:
            return []
        data = response.json()
        if not isinstance(data, dict):
            return []

        results: list[dict[str, str]] = []
        records = data.get("data", [])
        if not isinstance(records, list):
            return []
        for paste in records[:5]:
            if not isinstance(paste, dict):
                continue
            paste_id = paste.get("id")
            if not isinstance(paste_id, str) or not re.fullmatch(
                r"[A-Za-z0-9_-]{1,64}",
                paste_id,
            ):
                continue
            title = paste.get("title", "")
            results.append(
                {
                    "id": paste_id,
                    "title": str(title)[:200],
                    "url": f"https://pastebin.com/{paste_id}",
                }
            )
        return results
    except Exception as exc:
        log.debug("paste_search_error", error=type(exc).__name__)
        return []


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    checks: list[str] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    parsed = urlsplit(target if "://" in target else f"https://{target}")
    domain = (parsed.hostname or "").rstrip(".").lower()
    if not domain:
        return {
            "target": target,
            "observations": [],
            "error": "invalid_target",
        }
    if scope is None:
        return {
            "target": domain,
            "observations": [],
            "error": "scope_enforcer_required",
        }

    page_url = (
        parsed._replace(path=parsed.path or "/", query="", fragment="").geturl()
    )
    try:
        scope.assert_in_scope(page_url)
    except ScopeViolationError as exc:
        return {
            "target": domain,
            "observations": [],
            "error": str(exc),
        }

    active_checks = set(checks or ["emails", "pastebin"])
    unknown_checks = active_checks - {"emails", "pastebin"}
    if unknown_checks:
        return {
            "target": domain,
            "observations": [],
            "error": f"Unsupported OSINT checks: {', '.join(sorted(unknown_checks))}",
        }

    console.print(f"\n[module][+] Passive OSINT[/module] -> [target]{domain}[/target]")
    observations: list[dict[str, Any]] = []

    async with TalismanHTTPClient(
        proxy=proxy,
        timeout=15,
        verify_ssl=True,
        follow_redirects=False,
        scope=scope,
    ) as client:
        if "emails" in active_checks:
            emails = await _harvest_emails(domain, client, page_url)
            observations.append(
                {
                    "type": "public_email_references",
                    "count": len(emails),
                    "items": emails[:50],
                }
            )

        if "pastebin" in active_checks:
            pastes = await _check_pastebin(domain, client)
            observations.append(
                {
                    "type": "public_paste_references",
                    "count": len(pastes),
                    "items": pastes,
                }
            )

    console.print(
        f" Passive OSINT complete — {len(observations)} observation groups"
    )
    return {
        "target": domain,
        "observations": observations,
        "findings": [],
        "count": 0,
    }
