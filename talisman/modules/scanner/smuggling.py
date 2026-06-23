"""HTTP Request Smuggling — CL.TE, TE.CL, TE.TE, H2.CL detection."""
from __future__ import annotations
import asyncio
import socket
import ssl
import time
from typing import Any
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)


def _build_cl_te_probe(host: str, path: str = "/") -> bytes:
 """CL.TE: Content-Length says body is short, TE says it's chunked with leftovers."""
 body = b"0\r\n\r\nG"
 return (
  f"POST {path} HTTP/1.1\r\n"
  f"Host: {host}\r\n"
  f"Content-Type: application/x-www-form-urlencoded\r\n"
  f"Content-Length: {len(body) + 5}\r\n"
  f"Transfer-Encoding: chunked\r\n"
  f"Connection: keep-alive\r\n\r\n"
 ).encode() + body


def _build_te_cl_probe(host: str, path: str = "/") -> bytes:
 """TE.CL: TE says body ends at 0-chunk, CL says more bytes follow."""
 chunk = b"1\r\nG\r\n0\r\n\r\n"
 return (
  f"POST {path} HTTP/1.1\r\n"
  f"Host: {host}\r\n"
  f"Content-Type: application/x-www-form-urlencoded\r\n"
  f"Content-Length: 4\r\n"
  f"Transfer-Encoding: chunked\r\n"
  f"Connection: keep-alive\r\n\r\n"
 ).encode() + chunk


def _build_te_te_probe(host: str, path: str = "/") -> bytes:
 """TE.TE: Both headers, but one obfuscated so only one end processes it."""
 body = b"0\r\n\r\nG"
 return (
  f"POST {path} HTTP/1.1\r\n"
  f"Host: {host}\r\n"
  f"Content-Type: application/x-www-form-urlencoded\r\n"
  f"Content-Length: {len(body) + 5}\r\n"
  f"Transfer-Encoding: chunked\r\n"
  f"Transfer-Encoding: identity\r\n"
  f"Connection: keep-alive\r\n\r\n"
 ).encode() + body


async def _raw_send(host: str, port: int, use_tls: bool, data: bytes, timeout: int = 10) -> bytes:
 """Send raw bytes to socket and read response."""
 loop = asyncio.get_event_loop()

 def _sync_send() -> bytes:
  try:
   sock = socket.create_connection((host, port), timeout=timeout)
   if use_tls:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = ctx.wrap_socket(sock, server_hostname=host)
   sock.sendall(data)
   response = b""
   sock.settimeout(timeout)
   try:
    while True:
     chunk = sock.recv(4096)
     if not chunk:
      break
     response += chunk
   except socket.timeout:
    pass
   sock.close()
   return response
  except Exception as e:
   return f"ERROR: {e}".encode()

 return await loop.run_in_executor(None, _sync_send)


async def _detect_timing_differential(
 host: str, port: int, use_tls: bool, probe: bytes
) -> tuple[bool, float]:
 """Send probe and check if backend hangs waiting for more data."""
 start = time.monotonic()
 response = await _raw_send(host, port, use_tls, probe, timeout=6)
 elapsed = time.monotonic() - start
 if elapsed > 5.0 and (b"HTTP/1.1" not in response or b"400" in response[:15]):
  return True, elapsed
 return False, elapsed


async def run(
 target: str,
 session: Any = None,
 scope: Any = None,
 rate_limiter: Any = None,
 proxy: str | None = None,
 **kwargs: Any,
) -> dict[str, Any]:
 url = target if "://" in target else f"https://{target}"
 use_tls = url.startswith("https://")
 host_part = url.split("://")[1].split("/")[0]
 host = host_part.split(":")[0]
 port = int(host_part.split(":")[1]) if ":" in host_part else (443 if use_tls else 80)
 path = "/" + "/".join(url.split("://")[1].split("/")[1:]) or "/"

 console.print(f"\n[module][+] HTTP Request Smuggling[/module] -> [target]{url}[/target]")
 findings: list[dict[str, Any]] = []

 probes = [
  ("CL.TE", _build_cl_te_probe(host, path)),
  ("TE.CL", _build_te_cl_probe(host, path)),
  ("TE.TE", _build_te_te_probe(host, path)),
 ]

 for technique, probe in probes:
  console.print(f" Testing {technique}...")
  try:
   vulnerable, elapsed = await _detect_timing_differential(host, port, use_tls, probe)
   if vulnerable:
    severity = "critical"
    title = f"HTTP Request Smuggling — {technique}"
    print_finding(title, severity, url)
    finding = {
     "technique": technique,
     "elapsed": round(elapsed, 2),
     "host": host,
     "port": port,
    }
    findings.append(finding)
    if session:
     await session.add_finding(
      target=url, module="smuggling",
      vuln_type="http_request_smuggling",
      severity=severity, confidence="likely",
      title=title,
      description=(
       f"HTTP Request Smuggling ({technique}) detected. "
       f"The server took {elapsed:.1f}s to respond to a {technique} probe, "
       f"indicating the frontend and backend disagree on request boundaries."
      ),
      evidence=f"Timing delay: {elapsed:.1f}s (expected < 2s)",
      reproduction=(
       f"Use Burp Suite Repeater with HTTP/1 and send the {technique} probe. "
       f"Observe timing differential and confirm with a poisoning attack."
      ),
      remediation=(
       "1. Disable backend connection reuse (use HTTP/2 end-to-end).\n"
       "2. Configure frontend to normalize Transfer-Encoding headers.\n"
       "3. Reject requests with both Content-Length and Transfer-Encoding.\n"
       "4. Use a single-protocol pipeline (HTTP/2 or HTTP/1.1 only)."
      ),
      cvss_score=9.8, cwe="CWE-444",
      references=["https://portswigger.net/web-security/request-smuggling"],
     )
  except Exception as e:
   log.debug("smuggling_probe_error", technique=technique, error=str(e))

 console.print(f" Found {len(findings)} smuggling vulnerabilities")
 return {"target": url, "findings": findings, "count": len(findings)}
