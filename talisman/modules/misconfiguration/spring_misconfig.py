"""Spring Boot Actuator misconfiguration — full endpoint audit."""
from __future__ import annotations
import asyncio
import base64
import json
import re
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

ACTUATOR_ENDPOINTS = [
    ("/actuator",                    "Index — lists enabled endpoints",           "info"),
    ("/actuator/env",                "Environment variables (credential leak)",   "critical"),
    ("/actuator/configprops",        "All @ConfigurationProperties (passwords)",  "critical"),
    ("/actuator/beans",              "All Spring beans (recon)",                  "medium"),
    ("/actuator/mappings",           "All URL mappings (attack surface recon)",   "medium"),
    ("/actuator/httptrace",          "Recent HTTP request/response log",          "high"),
    ("/actuator/threaddump",         "JVM thread dump",                           "medium"),
    ("/actuator/heapdump",           "Full JVM heap dump (huge data exfil)",      "critical"),
    ("/actuator/loggers",            "Logger levels (can set to TRACE)",          "medium"),
    ("/actuator/metrics",            "Application metrics",                       "low"),
    ("/actuator/info",               "App info (version, git commit hash)",       "info"),
    ("/actuator/health",             "Health check (may expose DB info)",         "low"),
    ("/actuator/scheduledtasks",     "Scheduled task list",                       "low"),
    ("/actuator/caches",             "Cache contents",                            "medium"),
    ("/actuator/sessions",           "Active sessions (auth bypass)",             "critical"),
    ("/actuator/refresh",            "POST — force config reload",                "high"),
    ("/actuator/shutdown",           "POST — shutdown application (DoS)",         "critical"),
    ("/actuator/jolokia",            "JMX over HTTP (potential RCE)",             "critical"),
    ("/actuator/gateway/routes",     "Spring Cloud Gateway routes",               "high"),
    ("/actuator/conditions",         "Auto-config conditions",                    "low"),
    ("/actuator/auditevents",        "Audit events log",                          "medium"),
    ("/actuator/prometheus",         "Prometheus metrics",                        "low"),
    # Legacy paths
    ("/env",         "Legacy env endpoint", "critical"),
    ("/dump",        "Legacy thread dump",  "medium"),
    ("/health",      "Legacy health",       "low"),
    ("/info",        "Legacy info",         "low"),
    ("/jolokia",     "Legacy JMX",          "critical"),
    ("/metrics",     "Legacy metrics",      "low"),
    ("/trace",       "Legacy trace",        "high"),
    ("/loggers",     "Legacy loggers",      "medium"),
    ("/heapdump",    "Legacy heapdump",     "critical"),
]

CREDENTIAL_PATTERNS = re.compile(
    r"(?i)(password|passwd|secret|apikey|api_key|token|credential|auth|private_key|"
    r"access_key|secret_key|client_secret|db_pass|datasource\.password)\s*[=:\"']\s*([^\s,\"'}{]{4,})",
    re.IGNORECASE,
)


def _extract_credentials(text: str) -> list[dict[str, str]]:
    found = []
    for m in CREDENTIAL_PATTERNS.finditer(text):
        value = m.group(2).strip()
        if value.lower() not in ("null", "none", "true", "false", "", "***", "****", "xxxxxx"):
            found.append({"key": m.group(1), "value": value[:40] + "..." if len(value) > 40 else value})
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
    console.print(f"\n[module] Spring Boot Actuator Audit[/module] → [target]{url}[/target]")
    exposed: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
        async def _probe(path: str, desc: str, severity: str) -> None:
            full_url = url.rstrip("/") + path
            try:
                r = await client.get(full_url, timeout=10)
                if r.status_code == 200 and len(r.text) > 20:
                    entry: dict[str, Any] = {
                        "path": path,
                        "description": desc,
                        "severity": severity,
                        "size": len(r.text),
                        "status": r.status_code,
                    }

                    # Credential extraction from env/configprops
                    if path in ("/actuator/env", "/actuator/configprops", "/env"):
                        creds = _extract_credentials(r.text)
                        if creds:
                            entry["credentials_found"] = creds
                            severity = "critical"
                            title = f"Spring Actuator {path} — CREDENTIALS EXPOSED"
                        else:
                            title = f"Spring Actuator exposed: {path}"
                    elif path == "/actuator/heapdump":
                        title = "Spring Actuator heapdump accessible — full JVM memory dump"
                        entry["note"] = "Download and parse with Eclipse MAT or jhat for secrets"
                    elif path == "/actuator/sessions":
                        title = "Spring Actuator sessions — active session list (auth bypass possible)"
                        try:
                            sessions = r.json()
                            entry["session_count"] = len(sessions)
                        except Exception:
                            pass
                    elif path == "/actuator/jolokia":
                        title = "Spring Actuator Jolokia — JMX over HTTP (check for RCE via MBeans)"
                        severity = "critical"
                    else:
                        title = f"Spring Actuator exposed: {path}"

                    print_finding(title, severity, url)
                    exposed.append(entry)

                    if session:
                        await session.add_finding(
                            target=url, module="spring_actuator",
                            vuln_type="actuator_exposed",
                            severity=severity, confidence="confirmed",
                            title=title,
                            description=f"{desc}. Endpoint {full_url} returned {r.status_code} with {len(r.text)} bytes.",
                            evidence=r.text[:500],
                            request=f"GET {full_url} HTTP/1.1",
                            remediation=(
                                "1. Secure all actuator endpoints with Spring Security.\n"
                                "2. Expose only /health and /info publicly.\n"
                                "3. Add to application.properties:\n"
                                "   management.endpoints.web.exposure.include=health,info\n"
                                "   management.endpoint.health.show-details=never"
                            ),
                            cvss_score=9.1 if severity == "critical" else 7.5,
                            cwe="CWE-200",
                        )
            except Exception as e:
                log.debug("actuator_probe", path=path, error=str(e))

        tasks = [_probe(path, desc, sev) for path, desc, sev in ACTUATOR_ENDPOINTS]
        await asyncio.gather(*tasks, return_exceptions=True)

    console.print(f"  Found {len(exposed)} exposed actuator endpoints")
    return {"target": url, "exposed_endpoints": exposed, "count": len(exposed)}
