"""Subdomain takeover detection — 40+ service signatures."""
from __future__ import annotations
import asyncio
import re
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

TAKEOVER_SIGNATURES: list[dict[str, str]] = [
    {"cname": "github.io",            "provider": "GitHub Pages",     "fingerprint": "There isn't a GitHub Pages site here"},
    {"cname": "herokudns.com",        "provider": "Heroku",           "fingerprint": "No such app"},
    {"cname": "herokuapp.com",        "provider": "Heroku",           "fingerprint": "No such app"},
    {"cname": "cloudfront.net",       "provider": "AWS CloudFront",   "fingerprint": "Bad request"},
    {"cname": "s3-website",           "provider": "AWS S3",           "fingerprint": "NoSuchBucket"},
    {"cname": "s3.amazonaws.com",     "provider": "AWS S3",           "fingerprint": "NoSuchBucket"},
    {"cname": "fastly.net",           "provider": "Fastly",           "fingerprint": "Fastly error: unknown domain"},
    {"cname": "wpengine.com",         "provider": "WP Engine",        "fingerprint": "The site you were looking for"},
    {"cname": "pantheonsite.io",      "provider": "Pantheon",         "fingerprint": "404 error unknown site"},
    {"cname": "ghost.io",             "provider": "Ghost",            "fingerprint": "Domain has expired"},
    {"cname": "zendesk.com",          "provider": "Zendesk",          "fingerprint": "Help Center Closed"},
    {"cname": "myshopify.com",        "provider": "Shopify",          "fingerprint": "Sorry, this shop is currently unavailable"},
    {"cname": "azurewebsites.net",    "provider": "Azure Web Apps",   "fingerprint": "You do not have permission"},
    {"cname": "cloudapp.net",         "provider": "Azure",            "fingerprint": "no longer accepts connections"},
    {"cname": "trafficmanager.net",   "provider": "Azure Traffic Mgr","fingerprint": ""},
    {"cname": "ondigitalocean.app",   "provider": "DigitalOcean",     "fingerprint": "404 Not Found"},
    {"cname": "netlify.app",          "provider": "Netlify",          "fingerprint": "Not Found - Request ID"},
    {"cname": "vercel.app",           "provider": "Vercel",           "fingerprint": "The deployment could not be found"},
    {"cname": "surge.sh",             "provider": "Surge.sh",         "fingerprint": "project not found"},
    {"cname": "fly.dev",              "provider": "Fly.io",           "fingerprint": "404 Not Found"},
    {"cname": "readme.io",            "provider": "Readme.io",        "fingerprint": "Project doesnt exist"},
    {"cname": "statuspage.io",        "provider": "Statuspage",       "fingerprint": ""},
    {"cname": "freshdesk.com",        "provider": "Freshdesk",        "fingerprint": "There is no helpdesk"},
    {"cname": "helpscoutdocs.com",    "provider": "HelpScout",        "fingerprint": "No settings were found"},
    {"cname": "cargocollective.com",  "provider": "Cargo",            "fingerprint": "If you're moving your domain"},
    {"cname": "tumblr.com",           "provider": "Tumblr",           "fingerprint": "Whatever you were looking for"},
    {"cname": "squarespace.com",      "provider": "Squarespace",      "fingerprint": "No Such Account"},
    {"cname": "desk.com",             "provider": "Desk",             "fingerprint": "Please try again"},
    {"cname": "intercom.io",          "provider": "Intercom",         "fingerprint": "This page is reserved"},
    {"cname": "cname.gitbook.io",     "provider": "GitBook",          "fingerprint": ""},
    {"cname": "webflow.io",           "provider": "Webflow",          "fingerprint": "The page you are looking for"},
    {"cname": "airee.ru",             "provider": "Airee",            "fingerprint": ""},
    {"cname": "bitbucket.io",         "provider": "Bitbucket",        "fingerprint": "Repository not found"},
    {"cname": "launchrock.com",       "provider": "Launchrock",       "fingerprint": "It looks like you may have taken a wrong turn"},
    {"cname": "unbounce.com",         "provider": "Unbounce",         "fingerprint": "The requested URL was not found"},
    {"cname": "hubspot.com",          "provider": "HubSpot",          "fingerprint": "Domain not found"},
    {"cname": "tilda.cc",             "provider": "Tilda",            "fingerprint": "Please renew your subscription"},
    {"cname": "wixsite.com",          "provider": "Wix",              "fingerprint": "Error ConnectYourDomain"},
    {"cname": "firebaseapp.com",      "provider": "Firebase",         "fingerprint": "404 Not Found"},
    {"cname": "web.app",              "provider": "Firebase Hosting", "fingerprint": "404 Not Found"},
]


async def _check_takeover(
    subdomain: str,
    client: TalismanHTTPClient,
) -> dict[str, Any] | None:
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}/"
        try:
            r = await client.get(url, timeout=10, allow_redirects=True)
            body = r.text.lower()
            headers_str = str(r.headers).lower()

            for sig in TAKEOVER_SIGNATURES:
                cname_match = sig["cname"].lower() in headers_str or sig["cname"].lower() in body
                fp = sig.get("fingerprint", "").lower()
                fp_match = fp and fp in body

                if cname_match and fp_match:
                    return {
                        "subdomain": subdomain,
                        "provider": sig["provider"],
                        "cname_pattern": sig["cname"],
                        "fingerprint": sig["fingerprint"],
                        "url": url,
                        "status": r.status_code,
                    }
        except Exception:
            pass
    return None


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    subdomains: list[str] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    targets = subdomains or [target]
    console.print(f"\n[module] Subdomain Takeover Check[/module] — {len(targets)} targets")
    vulnerable: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:
        sem = asyncio.Semaphore(20)

        async def _check(sub: str) -> None:
            async with sem:
                result = await _check_takeover(sub, client)
                if result:
                    severity = "critical"
                    title = f"Subdomain takeover — {sub} → {result['provider']}"
                    print_finding(title, severity, sub)
                    vulnerable.append(result)
                    if session:
                        await session.add_finding(
                            target=sub, module="takeover",
                            vuln_type="subdomain_takeover",
                            severity=severity, confidence="confirmed",
                            title=title,
                            description=(
                                f"Subdomain '{sub}' points to {result['provider']} "
                                f"but the service/resource is unclaimed. "
                                f"An attacker can register the resource and serve content on this subdomain."
                            ),
                            evidence=f"Fingerprint: {result['fingerprint']}",
                            reproduction=f"Register the {result['provider']} resource for: {sub}",
                            remediation=(
                                "1. Remove the dangling DNS record immediately.\n"
                                "2. If the service is still needed, reclaim the resource on the provider.\n"
                                "3. Implement a process to audit DNS records when services are decommissioned."
                            ),
                            cvss_score=9.3, cwe="CWE-350",
                        )

        await asyncio.gather(*[_check(t) for t in targets], return_exceptions=True)

    console.print(f"  Found {len(vulnerable)} takeover candidates")
    return {"vulnerable": vulnerable, "count": len(vulnerable)}
