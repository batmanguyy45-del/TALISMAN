"""Secret scanning — JS files, HTML, headers, git exposure, env files."""
from __future__ import annotations
import asyncio
import base64
import re
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
 ("AWS Access Key",  re.compile(r'AKIA[0-9A-Z]{16}'), "critical"),
 ("AWS Secret Key",  re.compile(r'(?i)aws.{0,20}([\'"])[0-9a-zA-Z/+]{40}\1'), "critical"),
 ("Google OAuth",   re.compile(r'ya29\.[0-9A-Za-z_-]{20,}'), "critical"),
 ("GCP Service Account", re.compile(r'"type"\s*:\s*"service_account"'), "critical"),
 ("GitHub PAT",   re.compile(r'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}'), "critical"),
 ("GitHub App Token",  re.compile(r'ghs_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}'), "critical"),
 ("Slack Token",   re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'), "critical"),
 ("Slack Webhook",   re.compile(r'https://hooks\.slack\.com/services/[A-Z0-9]{9}/[A-Z0-9]{11}/[a-zA-Z0-9]{24}'), "high"),
 ("Stripe Secret Key",  re.compile(r'sk_(live|test)_[0-9a-zA-Z]{24,}'), "critical"),
 ("Stripe Publishable Key",re.compile(r'pk_(live|test)_[0-9a-zA-Z]{24,}'), "medium"),
 ("Stripe Webhook",  re.compile(r'whsec_[0-9a-zA-Z]{32,}'), "high"),
 ("SendGrid API Key",  re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'), "critical"),
 ("Twilio SID",   re.compile(r'AC[a-z0-9]{32}'), "high"),
 ("OpenAI API Key",  re.compile(r'sk-[A-Za-z0-9]{48}'), "critical"),
 ("Anthropic API Key",  re.compile(r'sk-ant-[A-Za-z0-9_-]{90,}'), "critical"),
 ("Mailgun API Key",  re.compile(r'key-[0-9a-zA-Z]{32}'), "high"),
 ("Firebase",    re.compile(r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'), "high"),
 ("JWT Token",    re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}'), "high"),
 ("Basic Auth in URL",  re.compile(r'https?://[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@'), "high"),
 ("RSA Private Key",  re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----'), "critical"),
 ("EC Private Key",  re.compile(r'-----BEGIN EC PRIVATE KEY-----'), "critical"),
 ("SSH Private Key",  re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'), "critical"),
 ("PGP Private Key",  re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'), "critical"),
 ("Postgres URL",   re.compile(r'postgres(?:ql)?://[^:]+:[^@]+@[^/\s]+/\S+'), "high"),
 ("MySQL URL",    re.compile(r'mysql://[^:]+:[^@]+@[^/\s]+/\S+'), "high"),
 ("MongoDB URL",   re.compile(r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^/\s]+'), "high"),
 ("Redis URL with pass", re.compile(r'redis://:[^@]+@[^/\s]+'), "high"),
 ("Heroku API Key",  re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'), "medium"),
 ("Azure Connection Str", re.compile(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+'), "critical"),
 ("Datadog API Key",  re.compile(r'(?i)datadog.{0,20}([a-zA-Z0-9]{40})'), "high"),
 ("Generic Password",  re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*[\'"]([^\'"]{8,})[\'"]'), "medium"),
 ("Generic API Key",  re.compile(r'(?i)api[_-]?key\s*[=:]\s*[\'"]([a-zA-Z0-9_\-]{16,})[\'"]'), "medium"),
 ("Generic Secret",  re.compile(r'(?i)secret\s*[=:]\s*[\'"]([a-zA-Z0-9_\-]{16,})[\'"]'), "medium"),
]

SENSITIVE_FILES = [
 "/.env", "/.env.local", "/.env.production", "/.env.backup",
 "/.env.old", "/.env.example", "/.env.development",
 "/config.json", "/config.yml", "/config.yaml",
 "/appsettings.json", "/appsettings.Development.json",
 "/secrets.json", "/credentials.json",
 "/.aws/credentials", "/.aws/config",
 "/wp-config.php", "/configuration.php",
 "/settings.py", "/local_settings.py",
 "/database.yml", "/storage.yml",
 "/.git/config",
]


async def _scan_content(content: str, source: str) -> list[dict[str, Any]]:
 found: list[dict[str, Any]] = []
 seen: set[str] = set()
 for name, pattern, severity in SECRET_PATTERNS:
  for match in pattern.finditer(content):
   val = match.group(0)
   key = f"{name}:{val[:20]}"
   if key not in seen:
    seen.add(key)
    found.append({
     "type": name,
     "severity": severity,
     "value": val[:80] + "..." if len(val) > 80 else val,
     "source": source,
     "context": content[max(0, match.start()-30):match.end()+30],
    })
 return found


async def run(
 target: str,
 session: Any = None,
 scope: Any = None,
 rate_limiter: Any = None,
 proxy: str | None = None,
 **kwargs: Any,
) -> dict[str, Any]:
 url = target if "://" in target else f"https://{target}"
 console.print(f"\n[module][+] Secret Scanner[/module] -> [target]{url}[/target]")
 all_secrets: list[dict[str, Any]] = []

 async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
  # — Scan main page ——————————————————————————————————
  try:
   r = await client.get(url)
   secrets = await _scan_content(r.text, "main_page")
   all_secrets.extend(secrets)
   # Extract JS file URLs
   js_urls = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', r.text)
  except Exception as e:
   log.debug("secrets_main_page", error=str(e))
   js_urls = []

  # — Scan JS files ——————————————————————————————————
  for js_path in js_urls[:20]:
   js_url = js_path if js_path.startswith("http") else url.rstrip("/") + "/" + js_path.lstrip("/")
   try:
    rjs = await client.get(js_url, timeout=10)
    if rjs.status_code == 200:
     js_secrets = await _scan_content(rjs.text, f"js:{js_path}")
     all_secrets.extend(js_secrets)
   except Exception:
    pass

  # — Probe sensitive files ——————————————————————————
  for path in SENSITIVE_FILES:
   try:
    rf = await client.get(url.rstrip("/") + path, timeout=8)
    if rf.status_code == 200 and len(rf.text) > 10:
     file_secrets = await _scan_content(rf.text, f"file:{path}")
     if file_secrets:
      all_secrets.extend(file_secrets)
     else:
      # File accessible but no pattern match — still a finding
      all_secrets.append({
       "type": "Sensitive file exposed",
       "severity": "high",
       "value": f"{path} ({len(rf.text)} bytes)",
       "source": "file_probe",
       "context": rf.text[:200],
      })
   except Exception:
    pass

 # Deduplicate and report
 seen_keys: set[str] = set()
 unique_secrets: list[dict[str, Any]] = []
 for s in all_secrets:
  key = f"{s['type']}:{s['value'][:20]}"
  if key not in seen_keys:
   seen_keys.add(key)
   unique_secrets.append(s)
   print_finding(f"Secret found: {s['type']}", s["severity"], url)
   if session:
    await session.add_finding(
     target=url, module="secrets",
     vuln_type="secret_exposure",
     severity=s["severity"], confidence="confirmed",
     title=f"Secret exposed: {s['type']}",
     description=f"{s['type']} found in {s['source']}",
     evidence=s["value"],
     remediation=(
      "1. Remove the secret immediately and rotate/revoke it.\n"
      "2. Audit git history for further exposure.\n"
      "3. Use environment variables or a secrets manager (AWS Secrets Manager, Vault).\n"
      "4. Add pre-commit hooks to prevent future secret commits."
     ),
     cwe="CWE-312",
    )

 console.print(f" Found {len(unique_secrets)} secrets")
 return {"target": url, "secrets": unique_secrets, "count": len(unique_secrets)}
