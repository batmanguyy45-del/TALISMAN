"""Parameter discovery and value fuzzing."""
from __future__ import annotations
import asyncio
import urllib.parse
from pathlib import Path
from typing import Any
from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console

log = get_logger(__name__)

COMMON_PARAMS = [
 "id", "user_id", "account", "username", "email", "name", "query",
 "q", "search", "s", "keyword", "term", "page", "p", "cat",
 "category", "type", "action", "cmd", "command", "exec", "run",
 "url", "uri", "path", "file", "dir", "folder", "src", "source",
 "dest", "destination", "redirect", "return", "next", "target",
 "host", "ip", "port", "debug", "test", "admin", "key", "token",
 "api_key", "secret", "pass", "password", "auth", "role", "level",
 "lang", "locale", "format", "output", "callback", "jsonp",
 "template", "theme", "style", "layout", "view", "mode",
 "sort", "order", "limit", "offset", "count", "size", "per_page",
 "filter", "field", "column", "table", "db", "database",
 "year", "month", "date", "start", "end", "from", "to",
]

INTERESTING_DIFFS = {"status_change", "size_change", "error_content"}

async def _probe_param(
 base_url: str,
 param: str,
 method: str,
 client: TalismanHTTPClient,
 baseline_status: int,
 baseline_size: int,
) -> dict[str, Any] | None:
 """Test if a parameter causes a meaningful response difference."""
 probe_values = ["1", "test", "'", "true", "null", "undefined", "0"]
 for val in probe_values:
  try:
   parsed = urllib.parse.urlparse(base_url)
   existing = dict(urllib.parse.parse_qsl(parsed.query))
   if param in existing:
    return None # Already known param
   test_params = {**existing, param: val}
   if method == "GET":
    r = await client.get(
     parsed._replace(query=urllib.parse.urlencode(test_params)).geturl(),
     timeout=8,
    )
   else:
    r = await client.post(base_url, data={param: val}, timeout=8)
   size_diff = abs(len(r.content) - baseline_size)
   if r.status_code != baseline_status or size_diff > 100:
    return {
     "param": param,
     "value": val,
     "method": method,
     "baseline_status": baseline_status,
     "new_status": r.status_code,
     "size_diff": size_diff,
     "interesting": True,
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
 methods: str = "GET",
 threads: int = 20,
 **kwargs: Any,
) -> dict[str, Any]:
 url = target if "://" in target else f"https://{target}"
 if scope is None:
  return {
   "target": url,
   "found": [],
   "count": 0,
   "error": "scope_enforcer_required",
  }
 try:
  scope.assert_in_scope(url)
 except ScopeViolationError as exc:
  return {
   "target": url,
   "found": [],
   "count": 0,
   "error": str(exc),
  }

 if not isinstance(methods, str):
  return {
   "target": url,
   "found": [],
   "count": 0,
   "error": "methods must be a comma-separated string containing GET and/or POST",
  }
 method_list = list(dict.fromkeys(
  method.strip().upper() for method in methods.split(",") if method.strip()
 ))
 unsupported_methods = sorted(set(method_list) - {"GET", "POST"})
 if not method_list or unsupported_methods:
  return {
   "target": url,
   "found": [],
   "count": 0,
   "error": (
    "unsupported fuzz methods: " + ", ".join(unsupported_methods)
    if unsupported_methods
    else "at least one fuzz method (GET or POST) is required"
   ),
  }

 skipped_methods: list[str] = []
 if "POST" in method_list:
  try:
   scope.assert_destructive_allowed(url, "POST")
  except ScopeViolationError:
   method_list.remove("POST")
   skipped_methods.append("POST")

 if not method_list:
  return {
   "target": url,
   "found": [],
   "count": 0,
   "skipped": True,
   "skipped_methods": skipped_methods,
   "reason": "POST parameter fuzzing requires explicit destructive-scope permission",
  }

 if isinstance(threads, bool) or not isinstance(threads, int) or threads < 1:
  return {
   "target": url,
   "found": [],
   "count": 0,
   "error": "threads must be a positive integer",
  }
 effective_threads = min(threads, int(scope.config.max_concurrent_requests))

 console.print(f"\\n[module][+] Parameter Fuzzer[/module] -> [target]{url}[/target]")
 params_to_test = list(COMMON_PARAMS)
 if wordlist:
  wl_path = Path(wordlist)
  if wl_path.exists() and wl_path.is_file() and not wl_path.is_symlink():
   with wl_path.open(encoding="utf-8", errors="replace") as handle:
    for line in handle:
     item = line.strip()
     if item and len(item) <= 128:
      params_to_test.append(item)
 params_to_test = list(dict.fromkeys(params_to_test))[:5000]

 console.print(
  f" Testing {len(params_to_test)} parameters × {len(method_list)} methods"
 )
 async with TalismanHTTPClient(
  proxy=proxy,
  timeout=10,
  scope=scope,
 ) as client:
  try:
   baseline_r = await client.get(url, timeout=8)
   baseline_status = baseline_r.status_code
   baseline_size = len(baseline_r.content)
  except Exception as exc:
   return {
    "target": url,
    "found": [],
    "count": 0,
    "error": f"baseline_request_failed: {type(exc).__name__}",
   }

  sem = asyncio.Semaphore(effective_threads)
  found: list[dict[str, Any]] = []

  async def _test(param: str, method: str) -> None:
   async with sem:
    result = await _probe_param(
     url, param, method, client, baseline_status, baseline_size
    )
    if result:
     found.append(result)
     console.print(
      f" [green]+[/green] {method} ?{param}= "
      f"(status: {result['new_status']}, size_diff: {result['size_diff']})"
     )

  tasks = [_test(param, method) for param in params_to_test for method in method_list]
  await asyncio.gather(*tasks, return_exceptions=True)

 console.print(f" Found {len(found)} interesting parameters")
 return {
  "target": url,
  "found": found,
  "count": len(found),
  "methods_run": method_list,
  "skipped_methods": skipped_methods,
 }
