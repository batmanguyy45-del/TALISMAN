"""Active Directory recon — LDAP enumeration, user/group/computer discovery."""
from __future__ import annotations
import asyncio
import json
from typing import Any
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)


def _ldap_enumerate(
 dc_ip: str, domain: str,
 username: str | None = None,
 password: str | None = None,
) -> dict[str, Any]:
 """Synchronous LDAP enumeration using ldap3."""
 result: dict[str, Any] = {
  "users": [], "groups": [], "computers": [],
  "spn_users": [], "asrep_users": [], "admins": [],
  "password_policy": {}, "trusts": [],
 }
 try:
  from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, ALL_ATTRIBUTES
  server = Server(dc_ip, get_info=ALL, use_ssl=False, port=389)
  if username and password:
   conn = Connection(
    server,
    user=f"{domain}\\{username}",
    password=password,
    authentication=NTLM,
    auto_bind=True,
   )
  else:
   conn = Connection(server, auto_bind=True) # Anonymous

  base_dn = ",".join(f"DC={p}" for p in domain.split("."))

  queries = {
   "users": ("(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2))",
      ["sAMAccountName", "mail", "userPrincipalName", "lastLogon", "pwdLastSet",
      "memberOf", "adminCount", "userAccountControl"]),
   "spn_users": ("(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))",
       ["sAMAccountName", "servicePrincipalName"]),
   "asrep_users": ("(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
       ["sAMAccountName"]),
   "admins": ("(&(objectClass=user)(adminCount=1))",
      ["sAMAccountName", "memberOf"]),
   "computers": ("(objectClass=computer)",
       ["dNSHostName", "operatingSystem", "operatingSystemVersion", "lastLogon"]),
   "groups": ("(objectClass=group)",
      ["sAMAccountName", "member", "memberOf", "adminCount"]),
  }

  for key, (filter_str, attrs) in queries.items():
   try:
    conn.search(base_dn, filter_str, SUBTREE, attributes=attrs, size_limit=500)
    for entry in conn.entries:
     obj: dict[str, Any] = {}
     for attr in attrs:
      val = getattr(entry, attr, None)
      if val:
       obj[attr] = str(val)
     result[key].append(obj)
   except Exception as e:
    log.debug("ldap_query_error", key=key, error=str(e))

  conn.unbind()
 except ImportError:
  result["error"] = "ldap3 not installed — run: pip install ldap3"
 except Exception as e:
  result["error"] = str(e)
 return result


async def run(
 target: str,
 session: Any = None,
 scope: Any = None,
 rate_limiter: Any = None,
 proxy: str | None = None,
 domain: str | None = None,
 dc_ip: str | None = None,
 username: str | None = None,
 password: str | None = None,
 collect: list[str] | None = None,
 **kwargs: Any,
) -> dict[str, Any]:
 host = dc_ip or target.replace("https://", "").replace("http://", "").split("/")[0]
 dom = domain or host
 console.print(f"\n[module][+] Active Directory Recon[/module] -> [target]{host}[/target]")
 console.print(f" Domain: {dom} | Auth: {'yes' if username else 'anonymous'}")

 loop = asyncio.get_event_loop()
 data = await loop.run_in_executor(None, _ldap_enumerate, host, dom, username, password)

 if "error" in data:
  console.print(f" [error]LDAP error: {data['error']}[/error]")
  return {"target": host, "error": data["error"]}

 # Report findings
 console.print(f" Users:  {len(data['users'])}")
 console.print(f" Kerberoastable: {len(data['spn_users'])}")
 console.print(f" AS-REP roastable: {len(data['asrep_users'])}")
 console.print(f" Admins:  {len(data['admins'])}")
 console.print(f" Computers: {len(data['computers'])}")
 console.print(f" Groups:  {len(data['groups'])}")

 if data["spn_users"] and session:
  names = [u.get("sAMAccountName", "") for u in data["spn_users"]]
  await session.add_finding(
   target=host, module="ad_recon", vuln_type="kerberoastable_accounts",
   severity="high", confidence="confirmed",
   title=f"Kerberoastable accounts: {len(data['spn_users'])}",
   description=f"Accounts with SPNs (Kerberoastable): {', '.join(names[:10])}",
   reproduction="Use GetUserSPNs.py or Rubeus to request TGS tickets and crack offline.",
   remediation=(
    "1. Audit all service accounts with SPNs.\n"
    "2. Ensure service account passwords are long (25+ chars) and random.\n"
    "3. Use Managed Service Accounts (MSA/gMSA) where possible."
   ),
   cwe="CWE-522",
  )

 if data["asrep_users"] and session:
  names = [u.get("sAMAccountName", "") for u in data["asrep_users"]]
  await session.add_finding(
   target=host, module="ad_recon", vuln_type="asrep_roastable",
   severity="high", confidence="confirmed",
   title=f"AS-REP roastable accounts: {len(data['asrep_users'])}",
   description=f"Accounts with pre-auth disabled: {', '.join(names[:10])}",
   reproduction="Use GetNPUsers.py or Rubeus to capture AS-REP hashes for offline cracking.",
   remediation="Enable Kerberos pre-authentication on all accounts. Remove DONT_REQUIRE_PREAUTH flag.",
   cwe="CWE-287",
  )

 return {"target": host, "domain": dom, **data}
