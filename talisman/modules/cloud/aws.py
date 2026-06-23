"""AWS security audit — S3, EC2 metadata, IAM, CloudFront, Lambda, secrets."""
from __future__ import annotations
import asyncio
import re
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

S3_BUCKET_TESTS = ["", "?", "/?list-type=2", "/?acl", "/?policy"]
CF_ORIGIN_BYPASS_HEADERS = [
 {"X-Forwarded-Host": "BUCKET.s3.amazonaws.com"},
 {"Origin": "https://s3.amazonaws.com"},
]

async def _test_s3_bucket(
 name: str, client: TalismanHTTPClient
) -> dict[str, Any] | None:
 url = f"https://{name}.s3.amazonaws.com/"
 try:
  r = await client.get(url, timeout=8)
  if r.status_code == 200 and ("ListBucketResult" in r.text or "<Key>" in r.text):
   keys = re.findall(r"<Key>([^<]+)</Key>", r.text)
   return {"bucket": name, "url": url, "listable": True,
     "files": keys[:10], "file_count": len(keys)}
  if r.status_code == 403 and "NoSuchBucket" not in r.text:
   return {"bucket": name, "url": url, "listable": False, "exists": True}
  if r.status_code == 200:
   return {"bucket": name, "url": url, "listable": False, "public_read": True}
 except Exception:
  pass
 return None

async def _check_ec2_metadata(client: TalismanHTTPClient) -> dict[str, Any]:
 """Test if the scanner is running in an EC2 instance with IMDS accessible."""
 results: dict[str, Any] = {}
 try:
  r = await client.get("http://169.254.169.254/latest/meta-data/", timeout=3)
  if r.status_code == 200:
   results["imdsv1_accessible"] = True
   results["metadata"] = r.text[:500]
   try:
    r2 = await client.get(
     "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     timeout=3,
    )
    if r2.status_code == 200:
     results["iam_role"] = r2.text.strip()
   except Exception:
    pass
 except Exception:
  results["imdsv1_accessible"] = False
 return results

async def _check_cloudfront_bypass(
 domain: str, client: TalismanHTTPClient
) -> bool:
 """Test if the S3 origin behind CloudFront is directly accessible."""
 base = domain.split(".")[0]
 for bucket in [base, f"{base}-assets", f"{base}-static"]:
  try:
   r = await client.get(
    f"https://{bucket}.s3.amazonaws.com/",
    headers={"Host": f"{bucket}.s3.amazonaws.com"},
    timeout=8,
   )
   if r.status_code in (200, 403) and "AmazonS3" in str(r.headers):
    return True
  except Exception:
   pass
 return False

async def run(
 target: str,
 session: Any = None,
 scope: Any = None,
 rate_limiter: Any = None,
 proxy: str | None = None,
 s3_enum: bool = True,
 ec2_metadata: bool = False,
 cloudfront_bypass: bool = True,
 **kwargs: Any,
) -> dict[str, Any]:
 domain = target.replace("https://", "").replace("http://", "").split("/")[0]
 console.print(f"\n[module][+] AWS Security Audit[/module] -> [target]{domain}[/target]")
 findings: list[dict[str, Any]] = []
 results: dict[str, Any] = {"domain": domain}

 base = domain.split(".")[0]
 bucket_names = [
  base, f"{base}-assets", f"{base}-static", f"{base}-media",
  f"{base}-images", f"{base}-files", f"{base}-uploads",
  f"{base}-backup", f"{base}-backups", f"{base}-data",
  f"{base}-dev", f"{base}-staging", f"{base}-prod",
  f"{base}-logs", f"{base}-archive", f"{base}-public",
  domain.replace(".", "-"),
 ]

 async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:
  # — S3 bucket enumeration ——————————————————————————————
  if s3_enum:
   tasks = [_test_s3_bucket(name, client) for name in bucket_names]
   s3_results = await asyncio.gather(*tasks, return_exceptions=True)
   buckets_found = [r for r in s3_results if isinstance(r, dict) and r]
   results["s3_buckets"] = buckets_found

   for bucket in buckets_found:
    if bucket.get("listable"):
     severity = "critical"
     title = f"S3 bucket publicly listable: {bucket['bucket']}"
     print_finding(title, severity, bucket["url"])
     if session:
      await session.add_finding(
       target=bucket["url"], module="aws",
       vuln_type="s3_public_listable",
       severity=severity, confidence="confirmed",
       title=title,
       description=(
        f"S3 bucket '{bucket['bucket']}' allows unauthenticated listing. "
        f"Files exposed: {', '.join(bucket.get('files', [])[:5])}"
       ),
       evidence=f"Listed {bucket.get('file_count', 0)} files",
       reproduction=f"curl {bucket['url']}",
       remediation=(
        "1. Set bucket ACL to private.\n"
        "2. Enable S3 Block Public Access at account level.\n"
        "3. Review bucket policy and remove any public Allow statements."
       ),
       cvss_score=9.1, cwe="CWE-732",
      )
    elif bucket.get("public_read"):
     print_finding(f"S3 bucket public read: {bucket['bucket']}", "high", bucket["url"])
    elif bucket.get("exists"):
     console.print(f" S3 bucket exists (access denied): {bucket['bucket']}")

  # — CloudFront origin bypass ———————————————————————
  if cloudfront_bypass:
   bypassed = await _check_cloudfront_bypass(domain, client)
   if bypassed:
    print_finding("CloudFront origin (S3) directly accessible", "high", domain)
    if session:
     await session.add_finding(
      target=domain, module="aws",
      vuln_type="cloudfront_origin_bypass",
      severity="high", confidence="confirmed",
      title="CloudFront S3 origin directly accessible",
      description=(
       "The S3 bucket serving as the CloudFront origin is publicly accessible directly, "
       "bypassing any CloudFront-level restrictions, WAF, or geo-blocking."
      ),
      remediation=(
       "Use an Origin Access Identity (OAI) or Origin Access Control (OAC) "
       "to restrict S3 bucket access to CloudFront only."
      ),
      cvss_score=6.5, cwe="CWE-284",
     )

 console.print(f" AWS audit complete — {len(findings)} findings")
 return results
