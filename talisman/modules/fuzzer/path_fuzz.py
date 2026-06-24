"""Directory/path fuzzer — brute force with extension testing and recursion."""
from __future__ import annotations
import asyncio
from pathlib import Path
from typing import Any
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
 console.print(f"\n[module][+] Path Fuzzer[/module] -> [target]{url}[/target]")

 paths_to_test = list(BUILT_IN_PATHS)

 # Load custom wordlist
 if wordlist:
  wl_path = Path(wordlist)
  if wl_path.exists():
   with open(wl_path) as f:
    paths_to_test.extend(line.strip() for line in f if line.strip())

 # Add extension variants
 ext_list = extensions or DEFAULT_EXTENSIONS[:5]
 base_paths = list(paths_to_test)
 for path in base_paths[:50]: # Limit ext testing to first 50
  if "." not in path:
   for ext in ext_list:
    paths_to_test.append(f"{path}.{ext}")

 paths_to_test = list(set(paths_to_test))
 console.print(f" Testing {len(paths_to_test)} paths...")

 found: list[dict[str, Any]] = []
 sem = asyncio.Semaphore(threads)

 async with TalismanHTTPClient(proxy=proxy, timeout=10) as client:
  async def _probe(path: str) -> None:
   async with sem:
    if scope and not scope.is_in_scope(f"{url}/{path}"):
     return
    result = await _probe_path(url, path, client)
    if result:
     found.append(result)
     status = result["status"]
     color = {200: "green", 403: "yellow", 401: "yellow",
        500: "red"}.get(status, "cyan")
     console.print(
      f" [{color}]{status}[/{color}] /{result['path']}"
      f" ({result['size']} bytes)"
      + (f" -> {result['redirect']}" if result["redirect"] else "")
     )
     # Flag sensitive finds
     interesting_paths = [".git", ".env", "phpinfo", "server-status",
          "actuator/env", "web.xml", "backup", ".sql"]
     if any(ip in result["path"].lower() for ip in interesting_paths):
      severity = "high" if status == 200 else "medium"
      if session:
       await session.add_finding(
        target=url, module="path_fuzzer",
        vuln_type="sensitive_path_exposure",
        severity=severity, confidence="confirmed",
        title=f"Sensitive path accessible: /{result['path']}",
        description=f"HTTP {status} for /{result['path']}",
        evidence=f"Status: {status}, Size: {result['size']}",
        request=f"GET /{result['path']} HTTP/1.1",
        cwe="CWE-200",
       )

  await asyncio.gather(*[_probe(p) for p in paths_to_test], return_exceptions=True)

 # Sort by status
 found.sort(key=lambda x: (x["status"] != 200, x["status"]))
 console.print(f"\n Found {len(found)} accessible paths")
 return {"target": url, "found": found, "count": len(found)}
