"""Directory/path fuzzer — brute force with extension testing and recursion."""
from __future__ import annotations
import asyncio
from pathlib import Path
from typing import Any
from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

BUILT_IN_PATHS = [
 # Admin panels
 "admin", "administrator", "admin/login", "admin/dashboard", "wp-admin",
 "panel", "cpanel", "phpmyadmin", "pma", "adminer", "dbadmin",
 "manager", "management", "console", "controlpanel", "adminpanel",
 # APIs
 "api", "api/v1", "api/v2", "api/v3", "graphql", "swagger",
 "swagger-ui", "swagger-ui.html", "api-docs", "openapi.json",
 "swagger.json", "v1", "v2", "rest", "graphiql",
 # Config / debug
 ".env", ".env.local", ".env.production", "config.json", "config.yml",
 "config.yaml", "settings.json", "appsettings.json", "secrets.json",
 "phpinfo.php", "info.php", "test.php", "debug.php",
 # Source control
 ".git", ".git/config", ".git/HEAD", ".svn", ".svn/entries",
 ".hg", ".hg/manifest", ".DS_Store", "Thumbs.db",
 # Backup files
 "backup.zip", "backup.tar.gz", "backup.sql", "db.sql", "database.sql",
 "dump.sql", "backup", "old", "bak", "archive",
 # Health / metrics
 "health", "healthz", "ping", "status", "metrics", "prometheus",
 "actuator", "actuator/health", "actuator/env", "actuator/mappings",
 # Auth
 "login", "signin", "logout", "register", "signup", "auth",
 "oauth", "oauth2", "oidc", "saml", "sso",
 # Common app paths
 "upload", "uploads", "files", "static", "assets", "public",
 "images", "img", "media", "downloads", "documents", "docs",
 # Server info
 "server-status", "server-info", "nginx_status", "stub_status",
 # WordPress
 "wp-login.php", "xmlrpc.php", "wp-json", "wp-content", "wp-includes",
 # Java
 "WEB-INF/web.xml", "WEB-INF/classes", "META-INF/MANIFEST.MF",
 # Node.js
 "package.json", "node_modules", ".npmrc",
 # Django
 "admin/", "django-admin", "accounts/login",
 # Rails
 "rails/info/properties", "rails/mailers",
]

DEFAULT_EXTENSIONS = ["php", "asp", "aspx", "jsp", "json", "xml", "bak", "txt", "log", "sql"]

INTERESTING_STATUS = {200, 204, 301, 302, 307, 401, 403, 405, 500}


async def _probe_path(
 base_url: str, path: str, client: TalismanHTTPClient
) -> dict[str, Any] | None:
 url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
 try:
  r = await client.get(url, allow_redirects=False, timeout=8)
  if r.status_code in INTERESTING_STATUS:
   return {
    "path": path,
    "url": url,
    "status": r.status_code,
    "size": len(r.content),
    "content_type": r.headers.get("content-type", ""),
    "redirect": r.headers.get("location", "") if r.status_code in (301, 302, 307) else "",
   }
 except Exception:
  pass
 return None


MAX_PATHS_PER_RUN = 5000
MAX_WORDLIST_ENTRIES = 4000
MAX_CONCURRENCY = 32


async def run(
 target: str,
 session: Any = None,
 scope: Any = None,
 rate_limiter: Any = None,
 proxy: str | None = None,
 wordlist: str | None = None,
 extensions: list[str] | None = None,
 threads: int = 30,
 recursion_depth: int = 1,
 **kwargs: Any,
) -> dict[str, Any]:
 url = target if "://" in target else f"https://{target}"
 if scope is None:
  return {
   "target": url,
   "found": [],
   "candidates": [],
   "findings": [],
   "count": 0,
   "error": "scope_enforcer_required",
  }
 try:
  scope.assert_in_scope(url)
 except ScopeViolationError as exc:
  return {
   "target": url,
   "found": [],
   "candidates": [],
   "findings": [],
   "count": 0,
   "error": str(exc),
  }

 if isinstance(threads, bool) or not isinstance(threads, int) or threads < 1:
  return {
   "target": url,
   "found": [],
   "candidates": [],
   "findings": [],
   "count": 0,
   "error": "threads must be a positive integer",
  }
 scope_concurrency = scope.config.max_concurrent_requests
 concurrency = min(threads, MAX_CONCURRENCY, scope_concurrency)

 console.print(f"\n[module][+] Path Fuzzer[/module] -> [target]{url}[/target]")

 paths_to_test = list(BUILT_IN_PATHS)

 # Load a bounded, regular-file wordlist. Never follow a symlink supplied as
 # the input file, and reject control characters and oversized path entries.
 if wordlist:
  wl_path = Path(wordlist).expanduser()
  if wl_path.is_symlink() or not wl_path.is_file():
   return {
    "target": url,
    "found": [],
    "candidates": [],
    "findings": [],
    "count": 0,
    "error": "wordlist must be a regular, non-symlink file",
   }
  try:
   with wl_path.open(encoding="utf-8", errors="replace") as handle:
    for _, line in zip(range(MAX_WORDLIST_ENTRIES), handle):
     item = line.strip()
     if (
      item
      and len(item) <= 256
      and "\\" not in item
      and not any(ord(char) < 0x20 or ord(char) == 0x7f for char in item)
     ):
      paths_to_test.append(item)
  except OSError as exc:
   return {
    "target": url,
    "found": [],
    "candidates": [],
    "findings": [],
    "count": 0,
    "error": f"could_not_read_wordlist: {type(exc).__name__}",
   }

 # Add only safe, bounded extension variants.
 ext_list: list[str] = []
 for extension in extensions or DEFAULT_EXTENSIONS[:5]:
  if not isinstance(extension, str):
   continue
  normalized = extension.strip().lstrip(".")
  if normalized and len(normalized) <= 12 and normalized.isalnum():
   ext_list.append(normalized)
 base_paths = list(paths_to_test)
 for path in base_paths[:50]:
  if "." not in path:
   for extension in ext_list:
    paths_to_test.append(f"{path}.{extension}")

 paths_to_test = list(dict.fromkeys(paths_to_test))[:MAX_PATHS_PER_RUN]
 console.print(
  f" Testing {len(paths_to_test)} paths (max concurrency {concurrency})..."
 )

 found: list[dict[str, Any]] = []
 sem = asyncio.Semaphore(concurrency)

 async with TalismanHTTPClient(
  proxy=proxy,
  timeout=10,
  scope=scope,
 ) as client:
  async def _probe(path: str) -> None:
   async with sem:
    candidate_url = f"{url.rstrip('/')}/{path.lstrip('/')}"
    if not scope.is_in_scope(candidate_url):
     return
    result = await _probe_path(url, path, client)
    if result:
     candidate = {
      **result,
      "confidence": "candidate",
      "classification": "path_access_observation",
      "requires_content_verification": True,
      "verification_required": (
       "Inspect the response body and confirm it contains sensitive data or "
       "configuration that should not be public. An HTTP status code, response "
       "size, login page, SPA fallback, or server error alone does not prove "
       "sensitive information disclosure."
      ),
     }
     found.append(candidate)
     status = candidate["status"]
     color = {200: "green", 403: "yellow", 401: "yellow", 500: "red"}.get(status, "cyan")
     console.print(
      f" [{color}]{status}[/{color}] /{candidate['path']}"
      f" ({candidate['size']} bytes)"
      + (f" -> {candidate['redirect']}" if candidate["redirect"] else "")
      + " [dim](candidate)[/dim]"
     )

  await asyncio.gather(*[_probe(path) for path in paths_to_test], return_exceptions=True)

 found.sort(key=lambda item: (item["status"] != 200, item["status"]))
 console.print(f"\n Found {len(found)} accessible-path candidates")
 return {
  "target": url,
  "found": found,
  "candidates": found,
  "findings": [],
  "count": len(found),
  "candidate_count": len(found),
  "confirmed_findings": 0,
 }
