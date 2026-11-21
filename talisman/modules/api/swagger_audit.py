"""OpenAPI / Swagger spec analysis and automated endpoint testing."""
from __future__ import annotations
import asyncio
import json
from typing import Any
from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

SWAGGER_PATHS = [
 "/swagger.json", "/swagger-ui.html", "/swagger-ui",
 "/api-docs", "/api-docs.json", "/openapi.json", "/openapi.yaml",
 "/v2/api-docs", "/v3/api-docs", "/v1/api-docs",
 "/api/swagger.json", "/api/v1/swagger.json", "/api/v2/swagger.json",
 "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
 "/docs", "/redoc", "/api/schema",
]


async def _find_spec(base_url: str, client: TalismanHTTPClient) -> tuple[str, dict] | None:
 """Auto-discover OpenAPI spec."""
 for path in SWAGGER_PATHS:
  url = base_url.rstrip("/") + path
  try:
   r = await client.get(url, timeout=8)
   if r.status_code == 200:
    try:
     data = r.json()
     if "paths" in data or "swagger" in data or "openapi" in data:
      return url, data
    except Exception:
     if "swagger" in r.text.lower() or "openapi" in r.text.lower():
      return url, {"raw": r.text[:1000]}
  except Exception:
   pass
 return None


def _extract_endpoints(spec: dict) -> list[dict[str, Any]]:
 """Extract all endpoints from OpenAPI spec."""
 endpoints: list[dict[str, Any]] = []
 base_path = spec.get("basePath", "")
 for path, path_item in spec.get("paths", {}).items():
  full_path = base_path + path
  for method, op in path_item.items():
   if method.lower() in ("get", "post", "put", "delete", "patch", "options"):
    params = op.get("parameters", [])
    endpoints.append({
     "path": full_path,
     "method": method.upper(),
     "operation_id": op.get("operationId", ""),
     "summary": op.get("summary", ""),
     "requires_auth": bool(op.get("security", spec.get("security", []))),
     "params": [p.get("name") for p in params],
     "tags": op.get("tags", []),
    })
 return endpoints


def _find_sensitive_endpoints(endpoints: list[dict]) -> list[dict]:
 """Flag endpoints that are likely sensitive or interesting."""
 sensitive_keywords = [
  "admin", "user", "account", "password", "token", "key",
  "secret", "auth", "login", "register", "delete", "update",
  "upload", "file", "export", "import", "backup", "config",
  "internal", "debug", "health", "metrics", "status",
 ]
 flagged: list[dict] = []
 for ep in endpoints:
  path_lower = ep["path"].lower()
  if any(kw in path_lower for kw in sensitive_keywords):
   ep["flagged_reason"] = next(kw for kw in sensitive_keywords if kw in path_lower)
   flagged.append(ep)
 return flagged


async def run(
 target: str,
 session: Any = None,
 scope: Any = None,
 rate_limiter: Any = None,
 proxy: str | None = None,
 spec_url: str | None = None,
 auth_header: str | None = None,
 test_endpoints: bool = True,
 **kwargs: Any,
) -> dict[str, Any]:
 url = target if "://" in target else f"https://{target}"
 if scope is None:
  return {
   "target": url,
   "spec_found": False,
   "endpoints": [],
   "findings": [],
   "candidates": [],
   "observations": [],
   "count": 0,
   "error": "scope_enforcer_required",
  }
 try:
  scope.assert_in_scope(url)
  if spec_url:
   scope.assert_in_scope(spec_url)
 except ScopeViolationError as exc:
  return {
   "target": url,
   "spec_found": False,
   "endpoints": [],
   "findings": [],
   "candidates": [],
   "observations": [],
   "count": 0,
   "error": str(exc),
  }

 console.print(f"\\n[module][+] Passive OpenAPI/Swagger Audit[/module] -> [target]{url}[/target]")
 spec_data: dict[str, Any] = {}
 spec_location = ""

 async with TalismanHTTPClient(
  proxy=proxy,
  timeout=15,
  verify_ssl=True,
  follow_redirects=False,
  scope=scope,
 ) as client:
  if spec_url:
   try:
    response = await client.get(spec_url, timeout=10)
    if response.status_code == 200:
     parsed = response.json()
     if isinstance(parsed, dict):
      spec_data = parsed
      spec_location = spec_url
   except Exception as exc:
    log.debug("openapi_explicit_spec_failed", error=type(exc).__name__)
  else:
   found = await _find_spec(url, client)
   if found:
    spec_location, spec_data = found

 if not spec_data:
  return {
   "target": url,
   "spec_found": False,
   "endpoints": [],
   "findings": [],
   "candidates": [],
   "observations": [],
   "count": 0,
   "active_endpoint_tests_performed": False,
  }

 endpoints = _extract_endpoints(spec_data)
 sensitive = _find_sensitive_endpoints(endpoints)
 observations: list[dict[str, Any]] = []
 candidates: list[dict[str, Any]] = []

 global_security = spec_data.get("security", [])
 for endpoint in sensitive:
  if not endpoint.get("requires_auth"):
   candidates.append({
    "type": "sensitive_operation_without_documented_security",
    "endpoint": {
     "path": endpoint.get("path"),
     "method": endpoint.get("method"),
     "operation_id": endpoint.get("operation_id"),
    },
    "confidence": "candidate",
    "verification_required": (
     "An OpenAPI security omission does not prove the server endpoint is public. "
     "Verify authorization behavior with a non-destructive request and a "
     "dedicated low-privilege account; inspect gateway and middleware policy."
    ),
   })

 if isinstance(global_security, list) and not global_security:
  observations.append({
   "type": "openapi_global_security_not_declared",
   "classification": "api_documentation_observation",
   "note": (
    "The OpenAPI document does not declare global security requirements. "
    "Runtime authorization may still be enforced outside the specification."
   ),
  })

 console.print(
  f" OpenAPI audit complete — {len(endpoints)} endpoints, "
  f"{len(candidates)} authorization candidates, {len(observations)} observations"
 )
 return {
  "target": url,
  "spec_found": True,
  "spec_url": spec_location,
  "endpoints": endpoints,
  "sensitive_endpoints": sensitive,
  "findings": [],
  "candidates": candidates,
  "observations": observations,
  "count": 0,
  "candidate_count": len(candidates),
  "observation_count": len(observations),
  "active_endpoint_tests_performed": False,
  "active_endpoint_tests_requested": bool(test_endpoints),
  "note": (
   "Automatic PUT, PATCH and DELETE probes are disabled. Documented sensitive "
   "operations require runtime authorization verification."
  ),
 }
