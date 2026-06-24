"""Subdomain enumeration — passive sources + active brute force + permutations."""
from __future__ import annotations
import asyncio
import json
import re
import ssl
import string
from pathlib import Path
from typing import Any
import aiodns
import httpx
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

PERMUTATION_PREFIXES = [
    "api", "dev", "staging", "stage", "test", "uat", "qa", "preprod", "prod",
    "www", "mail", "smtp", "pop", "imap", "ftp", "sftp", "ssh", "vpn",
    "admin", "panel", "dashboard", "portal", "app", "mobile", "m",
    "cdn", "static", "assets", "media", "images", "img", "files",
    "beta", "alpha", "demo", "sandbox", "internal", "intranet", "corp",
    "secure", "auth", "login", "sso", "iam", "identity",
    "backend", "server", "node", "api1", "api2", "api-v1", "api-v2",
    "jenkins", "gitlab", "github", "jira", "confluence", "bitbucket",
    "git", "svn", "ci", "cd", "deploy", "build", "docker", "k8s",
    "monitoring", "metrics", "grafana", "kibana", "elastic", "logs",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "backup", "archive", "old", "legacy", "v2", "new",
]

async def _crtsh(domain: str, client: TalismanHTTPClient) -> list[str]:
    found: list[str] = []
    try:
        r = await client.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=20)
        if r.status_code == 200:
            for entry in r.json():
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(f".{domain}") or sub == domain:
                        found.append(sub)
    except Exception as e:
        log.debug("crtsh_error", domain=domain, error=str(e))
    return list(set(found))

async def _hackertarget(domain: str, client: TalismanHTTPClient) -> list[str]:
    found: list[str] = []
    try:
        r = await client.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15)
        if r.status_code == 200 and "," in r.text:
            for line in r.text.splitlines():
                parts = line.split(",")
                if parts and parts[0].strip().endswith(f".{domain}"):
                    found.append(parts[0].strip())
    except Exception as e:
        log.debug("hackertarget_error", domain=domain, error=str(e))
    return found

async def _wayback(domain: str, client: TalismanHTTPClient) -> list[str]:
    found: list[str] = []
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=5000"
        r = await client.get(url, timeout=30)
        if r.status_code == 200:
            data = r.json()
            sub_re = re.compile(rf"https?://([a-z0-9._-]+\.{re.escape(domain)})", re.IGNORECASE)
            for row in data[1:]:
                if row:
                    m = sub_re.search(row[0])
                    if m:
                        found.append(m.group(1).lower())
    except Exception as e:
        log.debug("wayback_error", domain=domain, error=str(e))
    return list(set(found))

async def _dnsx_resolve(subdomain: str, resolver: aiodns.DNSResolver) -> dict[str, Any] | None:
    try:
        result = await resolver.query_dns(subdomain, "A")
        ips = [r.host for r in result]
        return {"host": subdomain, "ips": ips, "resolved": True}
    except Exception:
        return None

async def _wildcard_detect(domain: str, resolver: aiodns.DNSResolver) -> bool:
    random_sub = "talismanrandom123xyz789abc456." + domain
    try:
        await resolver.query_dns(random_sub, "A")
        log.warning("wildcard_detected", domain=domain)
        return True
    except Exception:
        return False

async def _permutation_generate(domain: str, base_subdomains: list[str]) -> list[str]:
    perms: set[str] = set()
    base_subs = [s.split(".")[0] for s in base_subdomains if "." in s][:50]
    for prefix in PERMUTATION_PREFIXES:
        perms.add(f"{prefix}.{domain}")
    for sub in base_subs[:20]:
        for prefix in ["dev", "staging", "test", "api", "v2", "new", "old"]:
            perms.add(f"{prefix}-{sub}.{domain}")
            perms.add(f"{sub}-{prefix}.{domain}")
        for i in range(1, 4):
            perms.add(f"{sub}{i}.{domain}")
    return list(perms)

async def run(
    target: str,
    session: Any,
    scope: Any,
    rate_limiter: Any,
    proxy: str | None = None,
    sources: list[str] | None = None,
    bruteforce: bool = False,
    wordlist: str | None = None,
    threads: int = 50,
    alive_only: bool = True,
    **kwargs: Any,
) -> dict[str, Any]:
    domain = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    active_sources = sources or ["crtsh", "hackertarget", "wayback", "permutation"]
    console.print(f"\n[module] Subdomain Enumeration[/module] → [target]{domain}[/target]")
    console.print(f"  Sources: {', '.join(active_sources)}")
    all_subdomains: set[str] = set()
    all_subdomains.add(domain)
    resolver = aiodns.DNSResolver(nameservers=["8.8.8.8", "1.1.1.1", "8.8.4.4"])
    is_wildcard = await _wildcard_detect(domain, resolver)
    if is_wildcard:
        console.print("  [warning] Wildcard DNS detected — results may be noisy[/warning]")
    async with TalismanHTTPClient(proxy=proxy, timeout=20, rotate_ua=True) as client:
        tasks: list[asyncio.Task] = []
        if "crtsh" in active_sources:
            tasks.append(asyncio.create_task(_crtsh(domain, client)))
        if "hackertarget" in active_sources:
            tasks.append(asyncio.create_task(_hackertarget(domain, client)))
        if "wayback" in active_sources:
            tasks.append(asyncio.create_task(_wayback(domain, client)))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                all_subdomains.update(result)
    if "permutation" in active_sources:
        perms = await _permutation_generate(domain, list(all_subdomains))
        all_subdomains.update(perms)
    if bruteforce and wordlist:
        wl_path = Path(wordlist)
        if wl_path.exists():
            with open(wl_path) as f:
                words = [line.strip() for line in f if line.strip()]
            for word in words[:10000]:
                all_subdomains.add(f"{word}.{domain}")
    console.print(f"  Found {len(all_subdomains)} candidates — resolving...")
    resolved: list[dict[str, Any]] = []
    sem = asyncio.Semaphore(threads)
    async def resolve_one(sub: str) -> None:
        async with sem:
            if not scope.is_in_scope(sub):
                return
            result = await _dnsx_resolve(sub, resolver)
            if result:
                resolved.append(result)
                if session:
                    await session.add_target(sub, ip=result["ips"][0] if result["ips"] else None)
    await asyncio.gather(*[resolve_one(s) for s in all_subdomains], return_exceptions=True)
    live = [r for r in resolved if r.get("resolved")]
    console.print(f"  [success]✓ {len(live)} live subdomains confirmed[/success]")
    for sub in sorted(live, key=lambda x: x["host"]):
        console.print(f"    [green]+[/green] {sub['host']} → {', '.join(sub['ips'][:2])}")
    return {"subdomains": resolved, "live_count": len(live), "wildcard": is_wildcard, "domain": domain}
