"""Continuous Monitoring — compares two sessions and alerts on new findings/targets."""
from __future__ import annotations
import json
import httpx
from typing import Any
from talisman.engine.session import SessionManager
from talisman.utils.logger import get_logger, console

log = get_logger(__name__)

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
            
        try:
            async with httpx.AsyncClient() as client:
                payload = {"content": alert_msg[:2000]}
                await client.post(webhook_url, json=payload)
                console.print(f"  [success]✓ Webhook alert sent to Discord/Slack[/success]")
        except Exception as e:
            console.print(f"  [warning]Failed to send webhook: {e}[/warning]")
            
    return {"new_targets": list(added_targets), "new_findings": added_findings}
