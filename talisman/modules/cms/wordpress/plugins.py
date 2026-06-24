"""WordPress plugin enumeration and CVE detection."""
from __future__ import annotations
import asyncio
import re
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

# Known critical plugin vulnerabilities
PLUGIN_VULN_DB: list[dict[str, Any]] = [
    {"slug": "contact-form-7",       "version_lt": "5.3.2", "cve": "CVE-2020-35489", "severity": "critical", "desc": "Unrestricted file upload"},
    {"slug": "elementor",            "version_lt": "3.6.3", "cve": "CVE-2022-1329",  "severity": "critical", "desc": "Authentication bypass"},
    {"slug": "woocommerce-payments", "version_lt": "5.6.2", "cve": "CVE-2023-28121", "severity": "critical", "desc": "Authentication bypass → admin takeover"},
    {"slug": "wp-file-manager",      "version_lt": "6.9",   "cve": "CVE-2020-25213", "severity": "critical", "desc": "Unauthenticated RCE"},
    {"slug": "duplicator",           "version_lt": "1.3.28","cve": "CVE-2020-11738", "severity": "critical", "desc": "Path traversal → arbitrary file read"},
    {"slug": "w3-total-cache",       "version_lt": "0.9.2.1","cve":"CVE-2019-6715",  "severity": "critical", "desc": "SSRF via subscriber+"},
    {"slug": "yoast-seo",            "version_lt": "17.3",  "cve": "CVE-2023-1227",  "severity": "medium",   "desc": "Reflected XSS"},
    {"slug": "wordfence",            "version_lt": "7.5.5", "cve": "CVE-2022-0215",  "severity": "high",     "desc": "CSRF to stored XSS"},
    {"slug": "wp-super-cache",       "version_lt": "1.7.2", "cve": "CVE-2021-24869", "severity": "high",     "desc": "Reflected XSS"},
    {"slug": "the-events-calendar",  "version_lt": "5.12.4","cve": "CVE-2021-24961", "severity": "high",     "desc": "SQL injection"},
    {"slug": "wpforms-lite",         "version_lt": "1.7.7", "cve": "CVE-2022-4328",  "severity": "high",     "desc": "Stored XSS via form"},
    {"slug": "advanced-custom-fields","version_lt":"6.1.6", "cve": "CVE-2023-30777", "severity": "high",     "desc": "Reflected XSS"},
    {"slug": "akismet",              "version_lt": "4.2.2", "cve": "CVE-2021-24916", "severity": "medium",   "desc": "Stored XSS"},
    {"slug": "classic-editor",       "version_lt": "1.6.3", "cve": "CVE-2021-24672", "severity": "medium",   "desc": "CSRF"},
    {"slug": "mailchimp-for-wp",     "version_lt": "4.8.7", "cve": "CVE-2023-1349",  "severity": "high",     "desc": "Stored XSS"},
]


def _compare_version(a: str, b: str) -> bool:
    """Return True if a < b."""
    def p(v: str) -> tuple[int, ...]:
        try:
            return tuple(int(x) for x in re.split(r"[.\-]", v)[:4])
        except ValueError:
            return (0, 0, 0, 0)
    return p(a) < p(b)


async def _detect_plugin(
    base_url: str, slug: str, client: TalismanHTTPClient
) -> dict[str, Any] | None:
    """Detect plugin via readme.txt which contains version info."""
    paths = [
        f"/wp-content/plugins/{slug}/readme.txt",
        f"/wp-content/plugins/{slug}/CHANGELOG.md",
        f"/wp-content/plugins/{slug}/{slug}.php",
    ]
    for path in paths:
        try:
            r = await client.get(base_url.rstrip("/") + path, timeout=8)
            if r.status_code == 200 and len(r.text) > 20:
                version = None
                m = re.search(r"Stable tag:\s*([0-9][0-9.]+)", r.text, re.IGNORECASE)
                if m:
                    version = m.group(1).strip()
                if not version:
                    m2 = re.search(r"Version:\s*([0-9][0-9.]+)", r.text, re.IGNORECASE)
                    if m2:
                        version = m2.group(1).strip()
                return {"slug": slug, "version": version, "detected_via": path}
        except Exception:
            pass
    return None


async def _passive_detect(base_url: str, html: str) -> list[str]:
    """Find plugins referenced in page HTML."""
    pattern = re.compile(r"/wp-content/plugins/([a-z0-9_-]+)/", re.IGNORECASE)
    return list(set(pattern.findall(html)))


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    method: str = "passive",
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    console.print(f"\n[module] WordPress Plugin Audit[/module] → [target]{url}[/target]")

    detected_plugins: list[dict[str, Any]] = []
    vulnerable: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
        # Passive: scan HTML for plugin references
        passive_slugs: list[str] = []
        try:
            r = await client.get(url)
            passive_slugs = await _passive_detect(url, r.text)
            console.print(f"  Passive: found {len(passive_slugs)} plugin references in HTML")
        except Exception:
            pass

        # Active: test all known vulnerable plugins
        known_slugs = [p["slug"] for p in PLUGIN_VULN_DB]
        all_slugs = list(set(passive_slugs + known_slugs))

        console.print(f"  Testing {len(all_slugs)} plugin slugs...")
        tasks = [_detect_plugin(url, slug, client) for slug in all_slugs]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, dict) and result:
                detected_plugins.append(result)
                slug = result["slug"]
                version = result.get("version")
                console.print(
                    f"  [green]+[/green] Plugin: {slug}"
                    + (f" v{version}" if version else " (version unknown)")
                )

                # CVE check
                for vuln in PLUGIN_VULN_DB:
                    if vuln["slug"] == slug:
                        if version and _compare_version(version, vuln["version_lt"]):
                            title = f"Vulnerable plugin: {slug} v{version} — {vuln['cve']}"
                            print_finding(title, vuln["severity"], url)
                            vulnerable.append({**vuln, "detected_version": version})
                            if session:
                                await session.add_finding(
                                    target=url, module="wordpress.plugins",
                                    vuln_type="vulnerable_plugin",
                                    severity=vuln["severity"], confidence="confirmed",
                                    title=title,
                                    description=(
                                        f"Plugin '{slug}' version {version} is vulnerable to "
                                        f"{vuln['cve']}: {vuln['desc']}. "
                                        f"Affected versions < {vuln['version_lt']}."
                                    ),
                                    remediation=f"Update {slug} to version {vuln['version_lt']} or later.",
                                    cwe="CWE-1104",
                                )
                        elif not version:
                            # Version unknown — flag as potential
                            print_finding(f"Plugin {slug} detected (version unknown) — check for {vuln['cve']}", "info", url)

    console.print(f"  Plugins: {len(detected_plugins)} detected, {len(vulnerable)} vulnerable")
    return {
        "target": url,
        "plugins": detected_plugins,
        "vulnerable": vulnerable,
    }
