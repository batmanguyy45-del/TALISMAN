"""OpenAPI / Swagger spec analysis and automated endpoint testing."""
from __future__ import annotations
import asyncio
import json
from typing import Any
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
                    "requires_auth": bool(op.get("security") or spec.get("securityDefinitions")),
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
    console.print(f"\n[module] Swagger/OpenAPI Audit[/module] → [target]{url}[/target]")

    async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
        # Find spec
        spec_data: dict = {}
        spec_location: str = ""
        if spec_url:
            try:
                r = await client.get(spec_url, timeout=10)
                spec_data = r.json()
                spec_location = spec_url
            except Exception as e:
                console.print(f"  [dim]Spec load error: {e}[/dim]")
        else:
            result = await _find_spec(url, client)
            if result:
                spec_location, spec_data = result

        if not spec_data:
            console.print("  No OpenAPI spec found")
            return {"target": url, "spec_found": False, "endpoints": [], "findings": []}

        console.print(f"  [success]✓ Spec found: {spec_location}[/success]")

        # Parse spec
        endpoints = _extract_endpoints(spec_data)
        sensitive = _find_sensitive_endpoints(endpoints)
        console.print(f"  Endpoints: {len(endpoints)} total, {len(sensitive)} sensitive")

        findings: list[dict[str, Any]] = []

        # Flag unauthenticated sensitive endpoints
        unauth_sensitive = [ep for ep in sensitive if not ep.get("requires_auth")]
        if unauth_sensitive:
            for ep in unauth_sensitive[:10]:
                title = f"Sensitive endpoint without auth: {ep['method']} {ep['path']}"
                print_finding(title, "high", url)
                findings.append({"type": "unauth_endpoint", "endpoint": ep})
                if session:
                    await session.add_finding(
                        target=url, module="swagger_audit",
                        vuln_type="unauth_endpoint",
                        severity="high", confidence="likely",
                        title=title,
                        description=f"Endpoint {ep['method']} {ep['path']} appears sensitive but lacks authentication requirement in spec.",
                        remediation="Add security requirements to all sensitive endpoints in the OpenAPI spec and enforce them server-side.",
                        cwe="CWE-306",
                    )

        # Test for unauthenticated access on "DELETE" and "PUT" endpoints
        if test_endpoints:
            headers: dict[str, str] = {}
            if auth_header:
                headers["Authorization"] = auth_header

            dangerous_methods = [ep for ep in endpoints if ep["method"] in ("DELETE", "PUT", "PATCH")]
            for ep in dangerous_methods[:5]:
                test_url = url.rstrip("/") + ep["path"]
                try:
                    r = await client.request(ep["method"], test_url, headers=headers, timeout=8)
                    if r.status_code not in (401, 403, 404, 405):
                        severity = "high" if r.status_code in (200, 201, 204) else "medium"
                        title = f"{ep['method']} {ep['path']} accepts request (status {r.status_code})"
                        print_finding(title, severity, url)
                        findings.append({"type": "dangerous_method_accepted", "endpoint": ep, "status": r.status_code})
                except Exception:
                    pass

        console.print(f"  Swagger audit complete — {len(findings)} findings")
        return {
            "target": url,
            "spec_found": True,
            "spec_url": spec_location,
            "endpoints": endpoints,
            "sensitive_endpoints": sensitive,
            "findings": findings,
        }
