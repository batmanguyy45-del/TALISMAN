"""Scoped AWS storage posture checks for explicitly authorized S3 buckets.

Automatic bucket-name guessing and scanner-host EC2 metadata requests are
intentionally disabled. Each bucket must be named by the operator and be
independently present in the assessment scope.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any

from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import console, print_finding

_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")


async def _test_s3_bucket(
    name: str,
    client: TalismanHTTPClient,
) -> dict[str, Any] | None:
    url = f"https://{name}.s3.amazonaws.com/"
    try:
        response = await client.get(url, timeout=8)
        if response.status_code == 200 and (
            "ListBucketResult" in response.text or "<Key>" in response.text
        ):
            keys = re.findall(r"<Key>([^<]+)</Key>", response.text)
            return {
                "bucket": name,
                "url": url,
                "listable": True,
                "files": keys[:10],
                "file_count": len(keys),
            }
        if response.status_code == 403 and "NoSuchBucket" not in response.text:
            return {
                "bucket": name,
                "url": url,
                "listable": False,
                "exists": True,
            }
        if response.status_code == 200:
            return {
                "bucket": name,
                "url": url,
                "listable": False,
                "public_read": True,
            }
    except Exception:
        return None
    return None


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    s3_enum: bool = False,
    s3_buckets: list[str] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    if scope is None:
        return {
            "target": target,
            "s3_buckets": [],
            "findings": [],
            "count": 0,
            "error": "scope_enforcer_required",
        }
    try:
        scope.assert_in_scope(target)
    except ScopeViolationError as exc:
        return {
            "target": target,
            "s3_buckets": [],
            "findings": [],
            "count": 0,
            "error": str(exc),
        }

    requested_buckets = list(dict.fromkeys(s3_buckets or []))
    if s3_enum and not requested_buckets:
        return {
            "target": target,
            "s3_buckets": [],
            "findings": [],
            "count": 0,
            "skipped": True,
            "reason": (
                "Automatic S3 bucket guessing is disabled. Supply explicit "
                "bucket names that are included in the assessment scope."
            ),
        }

    if len(requested_buckets) > 50:
        return {
            "target": target,
            "s3_buckets": [],
            "findings": [],
            "count": 0,
            "error": "A maximum of 50 explicit S3 buckets may be checked per run",
        }

    allowed_buckets: list[str] = []
    skipped_buckets: list[str] = []
    for bucket in requested_buckets:
        if not isinstance(bucket, str) or not _BUCKET_RE.fullmatch(bucket):
            skipped_buckets.append(str(bucket)[:100])
            continue
        bucket_url = f"https://{bucket}.s3.amazonaws.com/"
        if scope.is_in_scope(bucket_url):
            allowed_buckets.append(bucket)
        else:
            skipped_buckets.append(bucket)

    results: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    console.print(
        f"\n[module][+] Scoped AWS S3 Audit[/module] -> [target]{target}[/target]"
    )

    async with TalismanHTTPClient(
        proxy=proxy,
        timeout=12,
        verify_ssl=True,
        follow_redirects=False,
        scope=scope,
    ) as client:
        checked = await asyncio.gather(
            *(_test_s3_bucket(bucket, client) for bucket in allowed_buckets),
            return_exceptions=True,
        )

    for item in checked:
        if not isinstance(item, dict):
            continue
        results.append(item)
        if item.get("listable"):
            title = f"Explicitly scoped S3 bucket is publicly listable: {item['bucket']}"
            finding = {
                "bucket": item["bucket"],
                "url": item["url"],
                "severity": "high",
                "evidence": f"Unauthenticated listing returned {item['file_count']} keys",
            }
            findings.append(finding)
            print_finding(title, "high", item["url"])
            if session:
                await session.add_finding(
                    target=item["url"],
                    module="aws",
                    vuln_type="s3_public_listable",
                    severity="high",
                    confidence="confirmed",
                    title=title,
                    description=(
                        "An unauthenticated request to the explicitly scoped "
                        "bucket returned an S3 ListBucketResult."
                    ),
                    evidence=finding["evidence"],
                    reproduction=f"Send GET {item['url']} without credentials.",
                    remediation=(
                        "Restrict public bucket listing and access using S3 "
                        "Block Public Access and a least-privilege bucket policy."
                    ),
                    cwe="CWE-732",
                )
        elif item.get("public_read"):
            console.print(f" Public S3 object endpoint responds for bucket {item['bucket']}")

    return {
        "target": target,
        "s3_buckets": results,
        "skipped_buckets": skipped_buckets,
        "findings": findings,
        "count": len(findings),
    }
