"""Read-only IP, organization and ASN context lookup."""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import console, get_logger

log = get_logger(__name__)


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    parsed = urlsplit(target if "://" in target else f"https://{target}")
    domain = (parsed.hostname or "").rstrip(".").lower()
    if not domain:
        return {"domain": target, "error": "invalid_target"}

    if scope is None:
        return {"domain": domain, "error": "scope_enforcer_required"}

    try:
        scope.assert_in_scope(target)
    except ScopeViolationError as exc:
        return {"domain": domain, "error": str(exc)}

    console.print(f"\\n[module][+] WHOIS/ASN Context[/module] -> [target]{domain}[/target]")
    result: dict[str, Any] = {"domain": domain}

    # ipinfo.io is a passive data source in the default service allowlist.
    async with TalismanHTTPClient(
        proxy=proxy,
        timeout=15,
        verify_ssl=True,
        follow_redirects=False,
        scope=scope,
    ) as client:
        try:
            response = await client.get(
                f"https://ipinfo.io/{domain}/json",
                timeout=10,
            )
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict):
                    result.update({
                        "ip": data.get("ip"),
                        "org": data.get("org"),
                        "country": data.get("country"),
                        "region": data.get("region"),
                        "asn": (
                            data.get("org", "").split()[0]
                            if isinstance(data.get("org"), str) and data.get("org")
                            else None
                        ),
                    })
        except Exception as exc:
            log.debug("whois_lookup_failed", error=type(exc).__name__)

    return result
