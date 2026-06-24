"""Nuclei template runner — wraps nuclei binary."""
from __future__ import annotations
import asyncio
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    tags: str = "cve,misconfiguration,exposed-panels",
    severity: str = "critical,high,medium",
    templates_dir: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    console.print(f"\n[module] Nuclei Scanner[/module] → [target]{target}[/target]")

    nuclei_bin = shutil.which("nuclei")
    if not nuclei_bin:
        console.print("  [dim]nuclei not installed — skipping (install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)[/dim]")
        return {"target": target, "findings": [], "count": 0}

    cmd = [
        nuclei_bin,
        "-target", target,
        "-tags", tags,
        "-severity", severity,
        "-json",
        "-silent",
        "-no-color",
        "-rate-limit", "50",
    ]
    if proxy:
        cmd.extend(["-proxy", proxy])
    if templates_dir:
        cmd.extend(["-templates", templates_dir])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
        findings: list[dict[str, Any]] = []
        for line in stdout.decode().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                result = json.loads(line)
                sev = result.get("info", {}).get("severity", "info").lower()
                title = result.get("info", {}).get("name", "Nuclei finding")
                matched = result.get("matched-at", target)
                print_finding(f"[Nuclei] {title}", sev, matched)
                findings.append(result)
                if session:
                    await session.add_finding(
                        target=matched, module="nuclei",
                        vuln_type=result.get("template-id", "nuclei"),
                        severity=sev, confidence="confirmed",
                        title=f"[Nuclei] {title}",
                        description=result.get("info", {}).get("description", ""),
                        evidence=result.get("extracted-results", [""])[0] if result.get("extracted-results") else "",
                        cwe=result.get("info", {}).get("classification", {}).get("cwe-id", ""),
                    )
            except json.JSONDecodeError:
                pass
        console.print(f"  Nuclei: {len(findings)} findings")
        return {"target": target, "findings": findings, "count": len(findings)}
    except asyncio.TimeoutError:
        console.print("  [warning]Nuclei timed out after 5 minutes[/warning]")
        return {"target": target, "findings": [], "count": 0}
    except Exception as e:
        log.error("nuclei_runner_error", error=str(e))
        return {"target": target, "findings": [], "count": 0, "error": str(e)}
