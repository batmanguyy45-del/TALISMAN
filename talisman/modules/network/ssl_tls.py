"""SSL/TLS audit — version, ciphers, certificate chain."""
from __future__ import annotations
import asyncio
import ssl
import socket
from datetime import datetime
from typing import Any
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

async def run(
 target: str,
 session: Any = None,
 scope: Any = None,
 rate_limiter: Any = None,
 proxy: str | None = None,
 **kwargs: Any,
) -> dict[str, Any]:
 host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
 port = 443
 console.print(f"\n[module][+] SSL/TLS Audit[/module] -> [target]{host}:{port}[/target]")
 findings: list[dict[str, Any]] = []

 def _get_cert_info() -> dict[str, Any]:
  try:
   ctx = ssl.create_default_context()
   ctx.check_hostname = False
   ctx.verify_mode = ssl.CERT_NONE
   with socket.create_connection((host, port), timeout=10) as sock:
    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
     cert = ssock.getpeercert()
     proto = ssock.version()
     cipher = ssock.cipher()
     return {"cert": cert, "protocol": proto, "cipher": cipher}
  except Exception as e:
   return {"error": str(e)}

 loop = asyncio.get_event_loop()
 info = await loop.run_in_executor(None, _get_cert_info)

 if "error" in info:
  console.print(f" [dim]TLS error: {info['error']}[/dim]")
  return {"target": host, "findings": []}

 proto = info.get("protocol", "")
 cipher = info.get("cipher", ())
 cert = info.get("cert", {})

 console.print(f" Protocol: {proto}")
 console.print(f" Cipher: {cipher[0] if cipher else 'unknown'}")

 # Check for weak protocols
 if proto in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
  print_finding(f"Weak TLS protocol: {proto}", "high", host)
  findings.append({"issue": f"weak_tls_{proto}", "severity": "high"})
  if session:
   await session.add_finding(
    target=host, module="ssl_tls", vuln_type="weak_tls",
    severity="high", confidence="confirmed",
    title=f"Weak TLS protocol in use: {proto}",
    description=f"Server accepts {proto} connections which are cryptographically broken.",
    remediation="Disable TLS 1.0 and 1.1. Use TLS 1.2+ only. Prefer TLS 1.3.",
    cwe="CWE-326",
   )

 # Check cert expiry
 if cert and "notAfter" in cert:
  try:
   expiry_str = cert["notAfter"]
   expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
   days_left = (expiry - datetime.utcnow()).days
   if days_left < 30:
    sev = "critical" if days_left < 7 else "high" if days_left < 14 else "medium"
    print_finding(f"SSL certificate expires in {days_left} days", sev, host)
    findings.append({"issue": "cert_expiry", "days_left": days_left, "severity": sev})
  except Exception:
   pass

 console.print(f" TLS audit complete — {len(findings)} issues")
 return {"target": host, "protocol": proto, "findings": findings}
