"""OSINT — email harvest, GitHub dorks, S3 buckets, employee discovery."""
from __future__ import annotations
import asyncio
import re
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

# GitHub dork patterns for secret discovery
GITHUB_DORKS = [
    '"{domain}" password',
    '"{domain}" secret',
    '"{domain}" api_key',
    '"{domain}" apikey',
    '"{domain}" token',
    '"{domain}" aws_access_key',
    '"{domain}" db_password',
    '"{domain}" connectionstring',
    '"{domain}" .env',
    '"{domain}" private_key',
]

# Common S3 bucket naming patterns
def _s3_bucket_names(domain: str) -> list[str]:
    base = domain.split(".")[0]
    return [
        base, f"{base}-assets", f"{base}-static", f"{base}-media",
        f"{base}-images", f"{base}-files", f"{base}-uploads",
        f"{base}-backup", f"{base}-backups", f"{base}-data",
        f"{base}-dev", f"{base}-staging", f"{base}-prod",
        f"{base}-logs", f"{base}-archive", f"{base}-public",
        f"{base}-private", f"{base}-internal", f"{base}-cdn",
        f"{base}-email", f"{base}-reports", f"{base}-export",
        domain.replace(".", "-"),
    ]

async def _check_s3_bucket(name: str, client: TalismanHTTPClient) -> dict[str, Any] | None:
    url = f"https://{name}.s3.amazonaws.com/"
    try:
        r = await client.get(url, timeout=8)
        if r.status_code == 200:
            listable = "<ListBucketResult" in r.text or "<Key>" in r.text
            return {"bucket": name, "url": url, "public": True, "listable": listable}
        if r.status_code == 403:
            # Bucket exists but access denied
            return {"bucket": name, "url": url, "public": False, "exists": True}
        if "NoSuchBucket" in r.text:
            return None
    except Exception:
        pass
    return None

async def _harvest_emails(domain: str, client: TalismanHTTPClient) -> list[str]:
    emails: set[str] = set()
    email_re = re.compile(rf"[a-zA-Z0-9._%+\-]+@{re.escape(domain)}", re.IGNORECASE)
    sources = [
        f"https://api.hackertarget.com/emailfinder/?q={domain}",
    ]
    for url in sources:
        try:
            r = await client.get(url, timeout=10)
            if r.status_code == 200:
                found = email_re.findall(r.text)
                emails.update(found)
        except Exception:
            pass
    # Scrape main site
    try:
        r = await client.get(f"https://{domain}", timeout=10)
        found = email_re.findall(r.text)
        emails.update(found)
    except Exception:
        pass
    return list(emails)

async def _check_pastebin(domain: str, client: TalismanHTTPClient) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    try:
        r = await client.get(
            f"https://psbdmp.ws/api/v3/search/{domain}",
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            for paste in data.get("data", [])[:5]:
                results.append({
                    "id": paste.get("id"),
                    "title": paste.get("title", ""),
                    "url": f"https://pastebin.com/{paste.get('id')}",
                })
    except Exception:
        pass
    return results

async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    checks: list[str] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    active_checks = checks or ["emails", "s3_buckets", "pastebin"]
    console.print(f"\n[module]⚡ OSINT[/module] → [target]{domain}[/target]")
    results: dict[str, Any] = {"domain": domain}

    async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
        # — Email harvest ——————————————————————————————————————
        if "emails" in active_checks:
            emails = await _harvest_emails(domain, client)
            results["emails"] = emails
            if emails:
                console.print(f"  Emails found: {', '.join(emails[:5])}")
                if session:
                    await session.add_finding(
                        target=domain, module="osint",
                        vuln_type="email_exposure",
                        severity="info", confidence="confirmed",
                        title=f"Email addresses discovered for {domain}",
                        description=f"Found {len(emails)} email addresses: {', '.join(emails[:10])}",
                        remediation="Remove email addresses from public pages. Use contact forms instead.",
                        cwe="CWE-200",
                    )

        # — S3 bucket enumeration ———————————————————————————
        if "s3_buckets" in active_checks:
            bucket_names = _s3_bucket_names(domain)
            tasks = [_check_s3_bucket(name, client) for name in bucket_names]
            bucket_results = await asyncio.gather(*tasks, return_exceptions=True)
            found_buckets = [r for r in bucket_results if isinstance(r, dict) and r]
            results["s3_buckets"] = found_buckets
            for bucket in found_buckets:
                sev = "critical" if bucket.get("listable") else "high" if bucket.get("public") else "medium"
                title = f"S3 bucket {'publicly listable' if bucket.get('listable') else 'exists'}: {bucket['bucket']}"
                print_finding(title, sev, bucket["url"])
                if session and (bucket.get("public") or bucket.get("listable")):
                    await session.add_finding(
                        target=bucket["url"], module="osint",
                        vuln_type="s3_bucket_exposure",
                        severity=sev, confidence="confirmed",
                        title=title,
                        description=f"S3 bucket '{bucket['bucket']}' is {'publicly listable' if bucket.get('listable') else 'publicly accessible'}.",
                        evidence=bucket["url"],
                        reproduction=f"curl {bucket['url']}",
                        remediation="Set bucket ACL to private. Use bucket policies to restrict access.",
                        cvss_score=8.6 if bucket.get("listable") else 6.5,
                        cwe="CWE-732",
                    )

        # — Pastebin leaks ——————————————————————————————————
        if "pastebin" in active_checks:
            pastes = await _check_pastebin(domain, client)
            results["pastebin"] = pastes
            if pastes:
                console.print(f"  [warning]⚠ {len(pastes)} pastes mention {domain}[/warning]")
                for paste in pastes:
                    console.print(f"    → {paste.get('url')} — {paste.get('title', 'untitled')}")

    console.print(f"  OSINT complete")
    return results
