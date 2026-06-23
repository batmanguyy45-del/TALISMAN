"""SMB audit — share enumeration, null sessions, signing check, sensitive file search."""
from __future__ import annotations
import asyncio
import re
from pathlib import Path
from typing import Any
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

SENSITIVE_FILE_PATTERNS = [
 "*.xml", "*.config", "*.ini", "*.bat", "*.ps1", "*.vbs",
 "id_rsa*", "*.pem", "*.pfx", "*.kdbx", "*.rdp",
 "password*", "credentials*", "secret*", "*pass*",
 "Groups.xml", "Services.xml", "ScheduledTasks.xml",
 ".env", "web.config", "appsettings.json",
]

GPP_PASSWORD_PATTERN = re.compile(r'cpassword="([^"]+)"', re.IGNORECASE)


def _smb_enumerate(host: str, username: str = "", password: str = "",
     domain: str = "") -> dict[str, Any]:
 """Synchronous SMB enumeration using impacket."""
 result: dict[str, Any] = {"shares": [], "signing": None, "null_session": False,
        "sensitive_files": [], "gpp_credentials": []}
 try:
  from impacket.smbconnection import SMBConnection
  from impacket.smb import SMB_DIALECT
  conn = SMBConnection(host, host, timeout=10)

  # Signing check
  try:
   signing = conn.isSigningRequired()
   result["signing"] = signing
  except Exception:
   pass

  # Login (null session or with creds)
  try:
   if username:
    conn.login(username, password, domain)
   else:
    conn.login("", "") # Null session
    result["null_session"] = True
  except Exception as e:
   result["login_error"] = str(e)
   return result

  # Share enumeration
  try:
   shares = conn.listShares()
   for share in shares:
    share_name = share["shi1_netname"].rstrip("\x00")
    share_type = share["shi1_type"]
    share_remark = share["shi1_remark"].rstrip("\x00")
    # Test read access
    try:
     conn.listPath(share_name, "*")
     access = "READ"
    except Exception:
     access = "NO ACCESS"
    result["shares"].append({
     "name": share_name,
     "type": share_type,
     "remark": share_remark,
     "access": access,
    })
  except Exception as e:
   log.debug("smb_shares_error", error=str(e))

  # Search for sensitive files in readable shares
  for share in result["shares"]:
   if share["access"] == "READ":
    try:
     files = conn.listPath(share["name"], "*")
     for f in files:
      fname = f.get_longname()
      for pattern in SENSITIVE_FILE_PATTERNS:
       if _match_pattern(fname, pattern):
        result["sensitive_files"].append({
         "share": share["name"],
         "file": fname,
         "pattern": pattern,
        })
        break
    except Exception:
     pass

  # Check SYSVOL for GPP credentials
  try:
   sysvol_files = conn.listPath("SYSVOL", "**\\Groups.xml")
   for gpp_file in sysvol_files:
    try:
     content = b""
     conn.getFile("SYSVOL", gpp_file.get_longname(),
         lambda data: content.__iadd__(data))
     content_str = content.decode("utf-8", errors="ignore")
     for match in GPP_PASSWORD_PATTERN.finditer(content_str):
      encrypted = match.group(1)
      decrypted = _decrypt_gpp_password(encrypted)
      result["gpp_credentials"].append({
       "file": gpp_file.get_longname(),
       "encrypted": encrypted,
       "decrypted": decrypted,
      })
    except Exception:
     pass
  except Exception:
   pass

  conn.logoff()
 except ImportError:
  result["error"] = "impacket not installed — run: pip install impacket"
 except Exception as e:
  result["error"] = str(e)
 return result


def _match_pattern(filename: str, pattern: str) -> bool:
 import fnmatch
 return fnmatch.fnmatch(filename.lower(), pattern.lower())


def _decrypt_gpp_password(cpassword: str) -> str:
 """Decrypt GPP cpassword using known AES key (MS14-025)."""
 import base64
 try:
  from Crypto.Cipher import AES
  # Microsoft's published AES key for GPP
  key = bytes.fromhex(
   "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"
  )
  cpassword += "=" * ((4 - len(cpassword) % 4) % 4)
  password_bytes = base64.b64decode(cpassword)
  cipher = AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16)
  decrypted = cipher.decrypt(password_bytes)
  return decrypted.decode("utf-16-le", errors="ignore").rstrip("\x00")
 except Exception:
  return f"[decryption failed — raw: {cpassword[:20]}]"


async def run(
 target: str,
 session: Any = None,
 scope: Any = None,
 rate_limiter: Any = None,
 proxy: str | None = None,
 username: str = "",
 password: str = "",
 domain: str = "",
 enum_shares: bool = True,
 **kwargs: Any,
) -> dict[str, Any]:
 host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
 console.print(f"\n[module][+] SMB Audit[/module] -> [target]{host}[/target]")
 loop = asyncio.get_event_loop()
 data = await loop.run_in_executor(None, _smb_enumerate, host, username, password, domain)

 if "error" in data:
  console.print(f" [dim]SMB error: {data['error']}[/dim]")
  return {"target": host, "error": data["error"]}

 # Report signing
 if data["signing"] is False:
  print_finding("SMB signing not required — NTLM relay possible", "high", host)
  if session:
   await session.add_finding(
    target=host, module="smb_audit", vuln_type="smb_signing_disabled",
    severity="high", confidence="confirmed",
    title="SMB signing not required",
    description="SMB signing is not enforced, enabling NTLM relay attacks (e.g., via Responder + ntlmrelayx).",
    remediation="Enable: Computer Config -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> 'Microsoft network server: Digitally sign communications (always)' = Enabled",
    cvss_score=8.1, cwe="CWE-300",
   )

 # Null session
 if data["null_session"]:
  print_finding("SMB null session allowed", "medium", host)
  if session:
   await session.add_finding(
    target=host, module="smb_audit", vuln_type="smb_null_session",
    severity="medium", confidence="confirmed",
    title="SMB null session allowed",
    description="Anonymous/null session connection to SMB succeeded.",
    remediation="Restrict null session access via registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA -> RestrictAnonymous = 2",
    cwe="CWE-306",
   )

 # Shares
 if data["shares"]:
  readable = [s for s in data["shares"] if s["access"] == "READ"]
  console.print(f" Shares: {len(data['shares'])} total, {len(readable)} readable")
  for share in data["shares"]:
   console.print(f" {share['access']:10} {share['name']} ({share['remark']})")

 # Sensitive files
 if data["sensitive_files"]:
  print_finding(f"Sensitive files in SMB shares: {len(data['sensitive_files'])}", "high", host)
  for sf in data["sensitive_files"][:5]:
   console.print(f" \\\\{host}\\{sf['share']}\\{sf['file']}")

 # GPP credentials
 if data["gpp_credentials"]:
  print_finding(f"GPP credentials found (MS14-025): {len(data['gpp_credentials'])}", "critical", host)
  for cred in data["gpp_credentials"]:
   console.print(f" Decrypted: {cred['decrypted']}")
  if session:
   await session.add_finding(
    target=host, module="smb_audit", vuln_type="gpp_credentials",
    severity="critical", confidence="confirmed",
    title=f"GPP credentials in SYSVOL (MS14-025) — {len(data['gpp_credentials'])} found",
    description="Group Policy Preferences stored encrypted passwords using a publicly known AES key (MS14-025). Plaintext credentials recovered.",
    evidence="\n".join(f"{c['file']}: {c['decrypted']}" for c in data["gpp_credentials"][:3]),
    remediation="Delete all Group.xml/Services.xml/ScheduledTasks.xml files from SYSVOL that contain cpassword. Use LAPS for local admin passwords.",
    cvss_score=9.8, cwe="CWE-312",
   )

 return {"target": host, **data}
