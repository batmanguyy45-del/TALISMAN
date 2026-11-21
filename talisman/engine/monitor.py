"""Continuous Monitoring — compares two sessions and alerts on new findings/targets."""
from __future__ import annotations
import httpx
from urllib.parse import urlsplit
from typing import Any
from talisman.engine.session import SessionManager
from talisman.utils.logger import get_logger, console

log = get_logger(__name__)

_ALLOWED_WEBHOOK_HOSTS = {
    "discord.com": "/api/webhooks/",
    "discordapp.com": "/api/webhooks/",
    "hooks.slack.com": "/services/",
}


def _valid_webhook_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        expected_prefix = _ALLOWED_WEBHOOK_HOSTS.get((parsed.hostname or "").lower())
        return bool(
            parsed.scheme == "https"
            and parsed.username is None
            and parsed.password is None
            and parsed.port in {None, 443}
            and not parsed.query
            and not parsed.fragment
            and expected_prefix
            and parsed.path.startswith(expected_prefix)
            and "\r" not in value
            and "\n" not in value
        )
    except ValueError:
        return False

async def compare_sessions(old_session_name: str, new_session_name: str, webhook_url: str | None = None) -> dict[str, Any]:
    sm = SessionManager()
    if not sm.exists(old_session_name) or not sm.exists(new_session_name):
        raise ValueError("Both sessions must exist to compare.")
    
    old_sess = sm.get(old_session_name)
    new_sess = sm.get(new_session_name)
    
    async with old_sess:
        old_targets = await old_sess.get_targets()
        old_findings = await old_sess.get_findings()
        
    async with new_sess:
        new_targets = await new_sess.get_targets()
        new_findings = await new_sess.get_findings()
        
    old_target_hosts = {t['host'] for t in old_targets}
    new_target_hosts = {t['host'] for t in new_targets}
    added_targets = new_target_hosts - old_target_hosts
    
    def finding_hash(f: dict) -> str:
        return f"{f.get('target')}|{f.get('module')}|{f.get('vuln_type')}|{f.get('title')}"
        
    old_finding_hashes = {finding_hash(f) for f in old_findings}
    added_findings = [f for f in new_findings if finding_hash(f) not in old_finding_hashes]
    
    console.print(f"\n[module] Continuous Monitoring Diff[/module]")
    console.print(f"  [cyan]Old:[/cyan] {old_session_name} | [cyan]New:[/cyan] {new_session_name}")
    console.print(f"  New Targets Discovered: [green]{len(added_targets)}[/green]")
    console.print(f"  New Findings Discovered: [red]{len(added_findings)}[/red]")
    
    for t in added_targets:
        console.print(f"    [green]+[/green] Host: {t}")
    for f in added_findings:
        sev = f.get("severity", "info").upper()
        console.print(f"    [red]+[/red] [{sev}] {f.get('title')} on {f.get('target')}")
        
    if webhook_url and (added_targets or added_findings):
        alert_msg = f"🔔 **TALISMAN Monitor Alert**\n"
        if added_targets:
            alert_msg += f"\n**{len(added_targets)} New Targets:**\n" + "\n".join(f"- {t}" for t in list(added_targets)[:10])
        if added_findings:
            alert_msg += f"\n**{len(added_findings)} New Findings:**\n" + "\n".join(f"- [{f.get('severity', '').upper()}] {f.get('title')} ({f.get('target')})" for f in added_findings[:10])
            
        if not _valid_webhook_url(webhook_url):
            console.print(
                "  [warning]Webhook URL rejected. Only HTTPS Discord or Slack webhook endpoints are supported.[/warning]"
            )
        else:
            try:
                async with httpx.AsyncClient(
                    timeout=10,
                    verify=True,
                    follow_redirects=False,
                ) as client:
                    payload = {"content": alert_msg[:2000]}
                    response = await client.post(webhook_url, json=payload)
                    response.raise_for_status()
                    console.print("  [success]✓ Webhook alert sent[/success]")
            except Exception as exc:
                console.print(
                    f"  [warning]Failed to send webhook: {type(exc).__name__}[/warning]"
                )
            
    return {"new_targets": list(added_targets), "new_findings": added_findings}
