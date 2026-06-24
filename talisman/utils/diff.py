"""Session diff engine — compare findings between two sessions."""
from __future__ import annotations
from typing import Any
from talisman.engine.session import Session, SessionManager
from talisman.utils.logger import get_logger, console

log = get_logger(__name__)


async def diff_sessions(session1: str, session2: str) -> dict[str, Any]:
 """Compare two sessions and return what changed."""
 sm = SessionManager()
 s1 = sm.get(session1)
 s2 = sm.get(session2)

 async with s1:
  findings1 = await s1.get_findings()
  targets1 = await s1.get_targets()

 async with s2:
  findings2 = await s2.get_findings()
  targets2 = await s2.get_targets()

 # Key findings by (target, vuln_type, module)
 def _key(f: dict) -> str:
  return f"{f.get('target','')}__{f.get('vuln_type','')}__{f.get('module','')}"

 keys1 = {_key(f): f for f in findings1}
 keys2 = {_key(f): f for f in findings2}

 new_findings = [f for k, f in keys2.items() if k not in keys1]
 resolved = [f for k, f in keys1.items() if k not in keys2]
 persisted = [f for k, f in keys2.items() if k in keys1]

 targets_keys1 = {t.get("host") for t in targets1}
 targets_keys2 = {t.get("host") for t in targets2}
 new_targets = targets_keys2 - targets_keys1
 removed_targets = targets_keys1 - targets_keys2

 result = {
  "session1": session1,
  "session2": session2,
  "new_findings": new_findings,
  "resolved_findings": resolved,
  "persisted_findings": persisted,
  "new_targets": list(new_targets),
  "removed_targets": list(removed_targets),
 }

 # Print summary
 console.print(f"\n[bold cyan]Session Diff: {session1} -> {session2}[/bold cyan]")
 console.print(f" New findings:  {len(new_findings)}")
 console.print(f" Resolved:   {len(resolved)}")
 console.print(f" Persisted:  {len(persisted)}")
 console.print(f" New targets:  {len(new_targets)}")

 if new_findings:
  console.print("\n [bold green]+ New Findings:[/bold green]")
  for f in new_findings:
   sev = f.get("severity", "info")
   console.print(f" [+] [{sev.upper()}] {f.get('title','')[:60]}")

 if resolved:
  console.print("\n [bold red]- Resolved Findings:[/bold red]")
  for f in resolved:
   console.print(f" [-] {f.get('title','')[:60]}")

 return result
