"""Nuclei wrapper with explicit scope and conservative template execution."""
from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from typing import Any

from talisman.engine.scope import ScopeViolationError
from talisman.utils.logger import console, get_logger, print_finding

log = get_logger(__name__)

EXCLUDED_TEMPLATE_TAGS = "dos,intrusive,fuzz,bruteforce"


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
    console.print(
        f"\n[module][+] Nuclei Scanner[/module] -> [target]{target}[/target]"
    )

    if scope is None:
        return {
            "target": target,
            "findings": [],
            "count": 0,
            "error": "scope_enforcer_required",
        }
    try:
        scope.assert_in_scope(target)
    except ScopeViolationError as exc:
        return {"target": target, "findings": [], "count": 0, "error": str(exc)}

    nuclei_bin = shutil.which("nuclei")
    if not nuclei_bin:
        console.print(
            " [dim]nuclei not installed — skipping "
            "(install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)[/dim]"
        )
        return {"target": target, "findings": [], "count": 0, "skipped": True}

    if templates_dir:
        template_path = Path(templates_dir).expanduser()
        if template_path.is_symlink() or not template_path.is_dir():
            return {
                "target": target,
                "findings": [],
                "count": 0,
                "error": "templates_dir must be an existing, non-symlink directory",
            }
        templates_dir = str(template_path.resolve())

    # Do not inherit implicit active scans from the Nuclei defaults.
    # Redirects, intrusive templates, high concurrency and failed-request
    # retries are disabled/bounded explicitly here.
    request_rate = max(1, int(scope.config.max_requests_per_second))
    cmd = [
        nuclei_bin,
        "-target",
        target,
        "-tags",
        tags,
        "-severity",
        severity,
        "-exclude-tags",
        EXCLUDED_TEMPLATE_TAGS,
        "-json",
        "-silent",
        "-no-color",
        "-rate-limit",
        str(request_rate),
        "-concurrency",
        "5",
        "-retries",
        "0",
        "-timeout",
        "10",
        "-disable-redirects",
        "-restrict-local-network-access",
        "-no-interactsh",
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
        if proc.returncode not in (0, 1):
            return {
                "target": target,
                "findings": [],
                "count": 0,
                "error": f"nuclei exited with status {proc.returncode}",
            }

        findings: list[dict[str, Any]] = []
        out_of_scope_results = 0
        for line in stdout.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                continue

            matched = result.get("matched-at") or target
            if not isinstance(matched, str) or not scope.is_in_scope(matched):
                out_of_scope_results += 1
                continue

            info = result.get("info", {})
            if not isinstance(info, dict):
                continue
            sev = str(info.get("severity", "info")).lower()
            title = str(info.get("name", "Nuclei finding"))[:200]
            print_finding(f"[Nuclei] {title}", sev, matched)
            findings.append(result)

            if session:
                classification = info.get("classification", {})
                if not isinstance(classification, dict):
                    classification = {}
                extracted = result.get("extracted-results", [])
                evidence = extracted[0] if isinstance(extracted, list) and extracted else ""
                await session.add_finding(
                    target=matched,
                    module="nuclei",
                    vuln_type=str(result.get("template-id", "nuclei")),
                    severity=sev,
                    confidence="likely",
                    title=f"[Nuclei] {title}",
                    description=str(info.get("description", ""))[:2000],
                    evidence=str(evidence)[:1000],
                    cwe=str(classification.get("cwe-id", "")),
                )

        console.print(
            f" Nuclei: {len(findings)} in-scope candidates; "
            f"{out_of_scope_results} out-of-scope results discarded"
        )
        return {
            "target": target,
            "findings": findings,
            "count": len(findings),
            "out_of_scope_results_discarded": out_of_scope_results,
        }
    except TimeoutError:
        if "proc" in locals() and proc.returncode is None:
            proc.kill()
            await proc.wait()
        console.print(" [warning]Nuclei timed out after 5 minutes[/warning]")
        return {"target": target, "findings": [], "count": 0, "error": "timeout"}
    except Exception as exc:
        log.error("nuclei_runner_error", error=type(exc).__name__)
        return {
            "target": target,
            "findings": [],
            "count": 0,
            "error": type(exc).__name__,
        }
