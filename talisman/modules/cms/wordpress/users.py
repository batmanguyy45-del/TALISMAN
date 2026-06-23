"""WordPress user enumeration — all known methods."""
from __future__ import annotations
import asyncio
import re
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console

log = get_logger(__name__)


async def _author_redirect(base_url: str, client: TalismanHTTPClient) -> list[dict[str, Any]]:
 users: list[dict[str, Any]] = []
 for i in range(1, 25):
  try:
   r = await client.get(
    f"{base_url}/?author={i}",
    allow_redirects=False,
    timeout=8,
   )
   if r.status_code in (301, 302):
    loc = r.headers.get("location", "")
    m = re.search(r"/author/([^/]+)/?", loc)
    if m:
     users.append({"id": i, "username": m.group(1), "method": "author_redirect"})
   elif r.status_code == 200 and "author" in r.text.lower():
    m2 = re.search(r'class="author ([^"]+)"', r.text)
    if m2:
     uname = m2.group(1).replace("author-", "")
     users.append({"id": i, "username": uname, "method": "author_class"})
  except Exception:
   pass
 return users


async def _rest_api(base_url: str, client: TalismanHTTPClient) -> list[dict[str, Any]]:
 users: list[dict[str, Any]] = []
 try:
  r = await client.get(f"{base_url}/wp-json/wp/v2/users", timeout=10)
  if r.status_code == 200:
   data = r.json()
   if isinstance(data, list):
    for u in data:
     users.append({
      "id": u.get("id"),
      "username": u.get("slug", u.get("name", "")),
      "name": u.get("name", ""),
      "url": u.get("link", ""),
      "method": "rest_api",
     })
 except Exception:
  pass
 return users


async def _feed_author(base_url: str, client: TalismanHTTPClient) -> list[dict[str, Any]]:
 users: list[dict[str, Any]] = []
 try:
  r = await client.get(f"{base_url}/feed/", timeout=10)
  if r.status_code == 200:
   matches = re.findall(r"<dc:creator><!?\[CDATA\[([^\]]+)\]\]></dc:creator>", r.text)
   for username in set(matches):
    users.append({"username": username, "method": "rss_feed"})
 except Exception:
  pass
 return users


async def _sitemap_users(base_url: str, client: TalismanHTTPClient) -> list[dict[str, Any]]:
 users: list[dict[str, Any]] = []
 try:
  r = await client.get(f"{base_url}/wp-sitemap-users-1.xml", timeout=10)
  if r.status_code == 200:
   matches = re.findall(r"<loc>[^<]+/author/([^/]+)/?</loc>", r.text)
   for uname in set(matches):
    users.append({"username": uname, "method": "sitemap"})
 except Exception:
  pass
 return users


async def run(
 target: str,
 session: Any = None,
 scope: Any = None,
 rate_limiter: Any = None,
 proxy: str | None = None,
 all_methods: bool = True,
 **kwargs: Any,
) -> dict[str, Any]:
 url = target if "://" in target else f"https://{target}"
 console.print(f"\n[module][+] WordPress User Enumeration[/module] -> [target]{url}[/target]")

 all_users: dict[str, dict[str, Any]] = {}

 async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
  tasks = [
   _author_redirect(url, client),
   _rest_api(url, client),
   _feed_author(url, client),
   _sitemap_users(url, client),
  ]
  results = await asyncio.gather(*tasks, return_exceptions=True)
  for result in results:
   if isinstance(result, list):
    for u in result:
     uname = u.get("username", "")
     if uname and uname not in all_users:
      all_users[uname] = u

 user_list = list(all_users.values())
 if user_list:
  console.print(f" [warning][!] Found {len(user_list)} WordPress users:[/warning]")
  for u in user_list:
   console.print(f"  -> {u['username']} (via {u['method']})")
  if session:
   await session.add_finding(
    target=url, module="wordpress.users",
    vuln_type="user_enumeration",
    severity="medium", confidence="confirmed",
    title=f"WordPress user enumeration — {len(user_list)} users found",
    description=f"Users: {', '.join(u['username'] for u in user_list)}",
    remediation=(
     "1. Disable author archive pages.\n"
     "2. Restrict /wp-json/wp/v2/users to authenticated users.\n"
     "3. Change usernames from default 'admin'.\n"
     "4. Use a security plugin to block enumeration."
    ),
    cwe="CWE-200",
   )
 else:
  console.print(" No users found via automated methods")

 return {"target": url, "users": user_list, "count": len(user_list)}
