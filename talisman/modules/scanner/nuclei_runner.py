"""Nuclei wrapper with explicit scope and conservative template execution."""
from __future__ import annotations

import asyncio
import json
import os
import shutil
from pathlib import Path
from typing import Any

from talisman.engine.scope import ScopeViolationError
from talisman.utils.logger import console, get_logger, print_finding

log = get_logger(__name__)

EXCLUDED_TEMPLATE_TAGS = "dos,intrusive,fuzz,bruteforce"
EXCLUDED_TEMPLATE_TYPES = "code,file"
MAX_NUCLEI_OUTPUT_BYTES = 25 * 1024 * 1024
NUCLEI_OUTPUT_CHUNK_BYTES = 64 * 1024


class NucleiOutputLimitError(RuntimeError):
    """Raised when a Nuclei run exceeds its bounded output budget."""


async def _read_bounded_stdout(proc: asyncio.subprocess.Process) -> bytes:
    """Drain subprocess stdout without allowing unbounded memory growth."""
    if proc.stdout is None:
        raise RuntimeError("Nuclei stdout pipe was not created")

    output = bytearray()
    while True:
        chunk = await proc.stdout.read(NUCLEI_OUTPUT_CHUNK_BYTES)
        if not chunk:
            return bytes(output)
        if len(output) + len(chunk) > MAX_NUCLEI_OUTPUT_BYTES:
            raise NucleiOutputLimitError(
                f"Nuclei output exceeded {MAX_NUCLEI_OUTPUT_BYTES} bytes"
            )
        output.extend(chunk)


async def _collect_process_output(
    proc: asyncio.subprocess.Process,
) -> tuple[bytes, int]:
    """Drain output and wait for exit under the caller's overall deadline."""
    output = await _read_bounded_stdout(proc)
    return output, await proc.wait()


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

    # Nuclei resolves target hostnames in its own process. The current
    # integration cannot pin every connection to the IP validated by TALISMAN.
    # Fail closed unless the operator explicitly accepts this remaining DNS
    # boundary gap for this assessment.
    allow_unpinned_nuclei = os.environ.get(
        "TALISMAN_ALLOW_UNPINNED_NUCLEI", ""
    ).strip().lower() in {"1", "true", "yes"}
    if not allow_unpinned_nuclei:
        return {
            "target": target,
            "findings": [],
            "count": 0,
            "skipped": True,
            "reason": (
                "Nuclei uses its own DNS/network stack and cannot yet pin every "
                "connection to TALISMAN's scope-approved IP. Set "
                "TALISMAN_ALLOW_UNPINNED_NUCLEI=1 only when you explicitly accept "
                "that residual boundary risk for this authorized assessment."
            ),
        }

    # Nuclei owns its network stack and templates can issue POST/PUT/DELETE.
    # TALISMAN cannot apply its per-request method gate inside that subprocess,
    # so require explicit permission for destructive/state-changing probes
    # before even inspecting or launching the external binary.
    try:
        scope.assert_destructive_allowed(target, "POST")
    except ScopeViolationError as exc:
        return {
            "target": target,
            "findings": [],
            "count": 0,
            "skipped": True,
            "reason": (
                "Nuclei templates can issue state-changing requests that TALISMAN "
                "cannot method-gate individually. Explicit destructive-scope "
                f"permission is required: {exc}"
            ),
        }

    configured_rate = float(scope.config.max_requests_per_second)
    if configured_rate < 1.0:
        return {
            "target": target,
            "findings": [],
            "count": 0,
            "skipped": True,
            "reason": (
                "Nuclei only accepts an integer requests-per-second limit and "
                "cannot honor a scope ceiling below 1 request/second."
            ),
        }

    nuclei_bin = shutil.which("nuclei")
    if not nuclei_bin:
        console.print(
            " [dim]nuclei not installed — skipping "
            "(install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)[/dim]"
        )
        return {"target": target, "findings": [], "count": 0, "skipped": True}

    if proxy and not os.environ.get("TALISMAN_ALLOW_UNPINNED_PROXY", "").strip().lower() in {"1", "true", "yes"}:
        return {
            "target": target,
            "findings": [],
            "count": 0,
            "error": "proxy_not_allowed_without_explicit_TALISMAN_ALLOW_UNPINNED_PROXY=1",
        }

    if templates_dir and os.environ.get("TALISMAN_ALLOW_CUSTOM_NUCLEI_TEMPLATES", "").strip().lower() not in {"1", "true", "yes"}:
        return {
            "target": target,
            "findings": [],
            "count": 0,
            "error": "custom_nuclei_templates_disabled_by_default",
        }

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
    request_rate = int(configured_rate)
    request_concurrency = min(5, int(scope.config.max_concurrent_requests))
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
        # Nuclei templates are third-party executable policy. Require signed
        # templates and block local code/file protocols even after the operator
        # has accepted the separate unpinned-network opt-in.
        "-disable-unsigned-templates",
        "-exclude-type",
        EXCLUDED_TEMPLATE_TYPES,
        # Pin template behavior per run; operators update the template corpus
        # intentionally rather than letting the subprocess update itself.
        "-disable-update-check",
        "-json",
        "-silent",
        "-no-color",
        "-rate-limit",
        str(request_rate),
        "-concurrency",
        str(request_concurrency),
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
        # Nuclei performs its own network I/O and cannot acquire one shared
        # transport slot per request. Reserve the assessment's full HTTP
        # concurrency budget while it runs so other TALISMAN modules cannot
        # silently add traffic beyond the operator's configured concurrency.
        async with scope.exclusive_request_activity():
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, returncode = await asyncio.wait_for(
                _collect_process_output(proc),
                timeout=300,
            )
        if returncode not in (0, 1):
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
    except NucleiOutputLimitError:
        if "proc" in locals() and proc.returncode is None:
            proc.kill()
            await proc.wait()
        console.print(" [warning]Nuclei output limit exceeded; process stopped[/warning]")
        return {
            "target": target,
            "findings": [],
            "count": 0,
            "error": "output_limit",
        }
    except Exception as exc:
        if "proc" in locals() and proc.returncode is None:
            proc.kill()
            await proc.wait()
        log.error("nuclei_runner_error", error=type(exc).__name__)
        return {
            "target": target,
            "findings": [],
            "count": 0,
            "error": type(exc).__name__,
        }
