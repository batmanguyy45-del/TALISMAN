"""Active Directory Certificate Services — ESC1-ESC8 vulnerability detection."""
from __future__ import annotations
import asyncio
from typing import Any
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)


def _enumerate_templates(dc_ip: str, domain: str, username: str, password: str) -> list[dict]:
    """Enumerate AD CS templates via LDAP and check for ESC vulnerabilities."""
    templates: list[dict] = []
    try:
        from ldap3 import Server, Connection, NTLM, ALL, SUBTREE
        server = Server(dc_ip, get_info=ALL, port=389)
        conn = Connection(server, user=f"{domain}\\{username}",
                         password=password, authentication=NTLM, auto_bind=True)
        base_dn = ",".join(f"DC={p}" for p in domain.split("."))
        pki_dn = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{base_dn}"

        conn.search(
            pki_dn,
            "(objectClass=pKICertificateTemplate)",
            SUBTREE,
            attributes=[
                "cn", "msPKI-Certificate-Name-Flag",
                "msPKI-Enrollment-Flag", "pKIExtendedKeyUsage",
                "nTSecurityDescriptor", "msPKI-RA-Application-Policies",
            ],
        )
        for entry in conn.entries:
            template_info = {
                "name": str(entry.cn),
                "flags": str(entry["msPKI-Certificate-Name-Flag"]),
                "enrollment_flags": str(entry["msPKI-Enrollment-Flag"]),
                "ekus": [str(e) for e in entry["pKIExtendedKeyUsage"]],
                "vulnerabilities": [],
            }
            flags_val = 0
            try:
                flags_val = int(str(entry["msPKI-Certificate-Name-Flag"]))
            except Exception:
                pass

            # ESC1: Template allows SAN with client auth EKU
            # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
            san_flag = bool(flags_val & 0x00000001)
            client_auth_eku = "1.3.6.1.5.5.7.3.2" in template_info["ekus"]
            if san_flag and client_auth_eku:
                template_info["vulnerabilities"].append({
                    "esc": "ESC1",
                    "severity": "critical",
                    "desc": "Template allows enrollee to supply SAN with Client Auth EKU — forge certs for any user",
                })

            # ESC2: Any Purpose EKU
            any_purpose_eku = "2.5.29.37.0" in template_info["ekus"]
            if any_purpose_eku:
                template_info["vulnerabilities"].append({
                    "esc": "ESC2",
                    "severity": "high",
                    "desc": "Template has Any Purpose EKU — usable for client auth without restriction",
                })

            if template_info["vulnerabilities"]:
                templates.append(template_info)
        conn.unbind()
    except ImportError:
        templates.append({"error": "ldap3 not installed"})
    except Exception as e:
        templates.append({"error": str(e)})
    return templates


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
    **kwargs: Any,
) -> dict[str, Any]:
    host = dc_ip or target.replace("https://", "").replace("http://", "").split("/")[0]
    dom = domain or host
    console.print(f"\n[module]⚡ AD CS Audit (ESC1-ESC8)[/module] → [target]{host}[/target]")

    if not (username and password):
        console.print("  [dim]Credentials required: --user / --password[/dim]")
        return {"target": host, "findings": [], "count": 0}

    loop = asyncio.get_event_loop()
    templates = await loop.run_in_executor(
        None, _enumerate_templates, host, dom, username, password
    )

    findings: list[dict[str, Any]] = []
    for tmpl in templates:
        if "error" in tmpl:
            console.print(f"  [dim]AD CS error: {tmpl['error']}[/dim]")
            break
        for vuln in tmpl.get("vulnerabilities", []):
            title = f"AD CS {vuln['esc']}: {tmpl['name']} — {vuln['desc'][:60]}"
            print_finding(title, vuln["severity"], host)
            findings.append({"template": tmpl["name"], **vuln})
            if session:
                await session.add_finding(
                    target=host, module="ad_cs",
                    vuln_type=f"adcs_{vuln['esc'].lower()}",
                    severity=vuln["severity"], confidence="confirmed",
                    title=title,
                    description=(
                        f"Certificate template '{tmpl['name']}' is vulnerable to {vuln['esc']}. "
                        f"{vuln['desc']}"
                    ),
                    reproduction=(
                        f"certipy req -username {username}@{dom} -password {password} "
                        f"-ca 'CA-Name' -template {tmpl['name']} -upn administrator@{dom}"
                    ),
                    remediation=(
                        "1. Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag from template.\n"
                        "2. Remove Any Purpose EKU or restrict to specific purposes.\n"
                        "3. Restrict enrollment rights to specific security groups.\n"
                        "4. Enable CA Manager approval for sensitive templates."
                    ),
                    cvss_score=9.8, cwe="CWE-295",
                )

    console.print(f"  AD CS audit complete — {len(findings)} vulnerable templates")
    return {"target": host, "findings": findings, "count": len(findings)}
