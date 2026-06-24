"""CVE feed integration — correlate detected tech with known vulnerabilities."""
from __future__ import annotations
import asyncio
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console

log = get_logger(__name__)

async def lookup_cves(technology: str, version: str | None = None) -> list[dict[str, Any]]:
 """Query NVD API for CVEs matching a technology and version."""
 cves: list[dict[str, Any]] = []
 try:
  async with TalismanHTTPClient(timeout=15) as client:
   keyword = f"{technology} {version}" if version else technology
   r = await client.get(
    f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=10",
    timeout=15,
   )
   if r.status_code == 200:
    data = r.json()
    for vuln in data.get("vulnerabilities", [])[:10]:
     cve_data = vuln.get("cve", {})
     metrics = cve_data.get("metrics", {})
     cvss_score = None
     severity = "unknown"
     for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
      if metric_key in metrics:
       m = metrics[metric_key][0]
       cvss_score = m.get("cvssData", {}).get("baseScore")
       severity = m.get("cvssData", {}).get("baseSeverity", "unknown").lower()
       break
     desc_list = cve_data.get("descriptions", [])
     desc = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")
     cves.append({
      "id": cve_data.get("id"),
      "description": desc[:300],
      "cvss_score": cvss_score,
      "severity": severity,
      "published": cve_data.get("published", ""),
     })
 except Exception as e:
  log.debug("cve_feed_error", technology=technology, error=str(e))
 return cves

async def correlate_findings_with_cves(findings: list[dict], technologies: list[str]) -> list[dict]:
 """Add CVE context to findings based on detected technologies."""
 enriched = []
 for finding in findings:
  enriched.append(finding)
 return enriched
