"""Web crawler — discovers endpoints, forms, JS files, comments, and hidden params."""
from __future__ import annotations
import asyncio
import re
from collections import deque
from typing import Any
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console

log = get_logger(__name__)

JS_ENDPOINT_PATTERNS = [
 re.compile(r'["\'](/api/[a-zA-Z0-9/_\-?=&.]+)["\']'),
 re.compile(r'["\'](/v[0-9]+/[a-zA-Z0-9/_\-?=&.]+)["\']'),
 re.compile(r'fetch\(["\']([^"\']+)["\']'),
 re.compile(r'axios\.[a-z]+\(["\']([^"\']+)["\']'),
 re.compile(r'\.get\(["\']([^"\']+)["\']'),
 re.compile(r'\.post\(["\']([^"\']+)["\']'),
 re.compile(r'url:\s*["\']([^"\']+)["\']'),
 re.compile(r'href=["\']([^"\']+)["\']'),
 re.compile(r'action=["\']([^"\']+)["\']'),
]

COMMENT_PATTERNS = [
 re.compile(r'<!--(.*?)-->', re.DOTALL),
 re.compile(r'//\s*(TODO|FIXME|HACK|XXX|BUG|NOTE)[:\s](.+)'),
 re.compile(r'/\*\s*(TODO|FIXME|HACK|password|secret|key|token)[:\s](.+?)\*/', re.DOTALL | re.IGNORECASE),
]

def _same_domain(url1: str, url2: str) -> bool:
 try:
  return urlparse(url1).netloc == urlparse(url2).netloc
 except Exception:
  return False

def _normalize(url: str, base: str) -> str | None:
 try:
  full = urljoin(base, url)
  parsed = urlparse(full)
  if parsed.scheme not in ("http", "https"):
   return None
  return parsed._replace(fragment="").geturl()
 except Exception:
  return None

async def run(
 target: str,
 session: Any = None,
 scope: Any = None,
 rate_limiter: Any = None,
 proxy: str | None = None,
 depth: int = 3,
 js_parse: bool = True,
 forms: bool = True,
 wayback: bool = False,
 **kwargs: Any,
) -> dict[str, Any]:
 base_url = target if "://" in target else f"https://{target}"
 console.print(f"\n[module][+] Web Crawler[/module] -> [target]{base_url}[/target] (depth={depth})")

 visited: set[str] = set()
 queue: deque[tuple[str, int]] = deque([(base_url, 0)])
 endpoints: set[str] = set()
 forms_found: list[dict[str, Any]] = []
 js_endpoints: set[str] = set()
 interesting_comments: list[str] = []
 parameters: set[str] = set()

 async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
  while queue:
   url, current_depth = queue.popleft()
   if url in visited or current_depth > depth:
    continue
   if scope and not scope.is_in_scope(url):
    continue
   visited.add(url)

   try:
    r = await client.get(url, timeout=10)
    if r.status_code != 200:
     continue
    ct = r.headers.get("content-type", "")
    if "text/html" not in ct and "javascript" not in ct:
     continue

    html = r.text
    endpoints.add(url)

    # Extract URL query parameters
    parsed = urlparse(url)
    for param in re.findall(r'[?&]([a-zA-Z0-9_\-]+)=', parsed.query or ""):
     parameters.add(param)

    soup = BeautifulSoup(html, "lxml")

    # — Links ——————————————————————————————————
    for tag in soup.find_all(["a", "link"], href=True):
     href = tag.get("href", "")
     norm = _normalize(href, url)
     if norm and _same_domain(norm, base_url) and norm not in visited:
      if current_depth + 1 <= depth:
       queue.append((norm, current_depth + 1))

    # — Script src ——————————————————————————————
    for script in soup.find_all("script", src=True):
     src = script.get("src", "")
     norm = _normalize(src, url)
     if norm:
      endpoints.add(norm)

    # — Forms ———————————————————————————————————
    if forms:
     for form in soup.find_all("form"):
      action = form.get("action", url)
      method = form.get("method", "GET").upper()
      inputs = []
      for inp in form.find_all(["input", "textarea", "select"]):
       name = inp.get("name", "")
       itype = inp.get("type", "text")
       if name:
        inputs.append({"name": name, "type": itype})
        parameters.add(name)
      forms_found.append({
       "url": url,
       "action": _normalize(action, url) or action,
       "method": method,
       "inputs": inputs,
      })

    # — JS endpoint extraction ————————————————
    if js_parse:
     for script in soup.find_all("script"):
      script_text = script.string or ""
      for pat in JS_ENDPOINT_PATTERNS:
       for m in pat.finditer(script_text):
        ep = m.group(1)
        if ep.startswith("/") or ep.startswith("http"):
         norm = _normalize(ep, url)
         if norm:
          js_endpoints.add(norm)

    # — Comments ——————————————————————————————
    for pat in COMMENT_PATTERNS:
     for m in pat.finditer(html):
      comment = m.group(0)[:200].strip()
      if len(comment) > 20 and any(
       kw in comment.lower()
       for kw in ["todo", "fixme", "password", "secret", "key", "token", "admin", "debug"]
      ):
       interesting_comments.append(comment)

   except Exception as e:
    log.debug("crawl_error", url=url, error=str(e))

  # — Inline JS file scanning ———————————————————
  if js_parse:
   js_files = [e for e in endpoints if ".js" in e][:20]
   for js_url in js_files:
    if js_url in visited:
     continue
    try:
     rjs = await client.get(js_url, timeout=8)
     if rjs.status_code == 200:
      for pat in JS_ENDPOINT_PATTERNS:
       for m in pat.finditer(rjs.text):
        ep = m.group(1)
        if ep.startswith("/") or ep.startswith("http"):
         norm = _normalize(ep, base_url)
         if norm:
          js_endpoints.add(norm)
    except Exception:
     pass

 all_endpoints = sorted(endpoints | js_endpoints)
 console.print(f" Pages crawled: {len(visited)}")
 console.print(f" Endpoints found: {len(all_endpoints)}")
 console.print(f" Forms found: {len(forms_found)}")
 console.print(f" Parameters discovered: {len(parameters)}")
 if interesting_comments:
  console.print(f" [warning][!] {len(interesting_comments)} interesting code comments found[/warning]")

 return {
  "base_url": base_url,
  "pages_crawled": len(visited),
  "endpoints": all_endpoints,
  "forms": forms_found,
  "js_endpoints": sorted(js_endpoints),
  "parameters": sorted(parameters),
  "comments": interesting_comments[:20],
 }
