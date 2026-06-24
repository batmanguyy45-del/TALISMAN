"""Dependency confusion scanner — detects vulnerable dependency resolution patterns in package files."""
from __future__ import annotations
import asyncio
import json
import re
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

PACKAGE_FILES = [
    "/package.json",
    "/package-lock.json",
    "/requirements.txt",
    "/Pipfile",
    "/Pipfile.lock",
    "/Gemfile",
    "/Gemfile.lock",
    "/composer.json",
    "/composer.lock",
    "/go.mod",
    "/go.sum",
    "/Cargo.toml",
    "/Cargo.lock",
    "/yarn.lock",
    "/pnpm-lock.yaml",
    "/pyproject.toml",
    "/setup.py",
    "/setup.cfg",
    "/build.gradle",
    "/pom.xml",
    "/nuget.config",
    "/packages.config",
]

INTERNAL_PACKAGE_PATTERNS = [
    r"@[a-z]+/internal-",
    r"@[a-z]+-internal/",
    r"@[a-z]+-private/",
    r"@[a-z]+-core/",
    r"internal-[a-z]+",
    r"private-[a-z]+",
    r"[a-z]+-internal",
    r"[a-z]+-private",
    r"[a-z]+-backend",
    r"[a-z]+-frontend",
    r"[a-z]+-common",
    r"[a-z]+-utils",
    r"[a-z]+-lib",
    r"[a-z]+-sdk",
    r"[a-z]+-auth",
    r"[a-z]+-api",
    r"[a-z]+-config",
    r"[a-z]+-core",
    r"[a-z]+-shared",
    r"[a-z]+-platform",
]


async def _fetch_package_file(
    url: str, path: str, client: TalismanHTTPClient,
) -> dict[str, Any] | None:
    """Fetch a package management file from the target."""
    test_url = url.rstrip("/") + path
    try:
        r = await client.get(test_url, timeout=8)
        if r.status_code == 200 and len(r.content) > 100:
            content = r.text
            # Determine package manager type from path
            pm_type = "unknown"
            if "package.json" in path:
                pm_type = "npm"
            elif "requirements.txt" in path or "Pipfile" in path or "pyproject" in path or "setup.py" in path:
                pm_type = "pip"
            elif "Gemfile" in path:
                pm_type = "rubygems"
            elif "composer.json" in path:
                pm_type = "composer"
            elif "go.mod" in path:
                pm_type = "go"
            elif "Cargo.toml" in path:
                pm_type = "cargo"
            elif "build.gradle" in path or "pom.xml" in path:
                pm_type = "maven"
            elif "nuget" in path:
                pm_type = "nuget"
            elif "yarn.lock" in path or "pnpm-lock" in path:
                pm_type = "npm"

            return {
                "path": path,
                "pm_type": pm_type,
                "content": content,
                "size": len(content),
            }
    except Exception:
        pass
    return None


def _extract_dependencies(content: str, pm_type: str) -> list[dict[str, Any]]:
    """Extract dependency names from package file content."""
    deps: list[dict[str, Any]] = []

    if pm_type == "npm":
        try:
            data = json.loads(content)
            for section in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
                if section in data and isinstance(data[section], dict):
                    for name, version in data[section].items():
                        deps.append({"name": name, "version": str(version), "section": section})
        except (json.JSONDecodeError, ValueError):
            pass

    elif pm_type == "pip":
        for line in content.split("\n"):
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("-"):
                # Handle various formats: package==version, package>=version, etc.
                match = re.match(r"^([a-zA-Z0-9_.-]+)\s*[><=!~]+\s*(\S+)", line)
                if match:
                    deps.append({"name": match.group(1), "version": match.group(2), "section": "dependencies"})
                elif re.match(r"^[a-zA-Z0-9_.-]+$", line):
                    deps.append({"name": line, "version": "*", "section": "dependencies"})

    elif pm_type == "rubygems":
        for line in content.split("\n"):
            line = line.strip()
            match = re.match(r'gem\s+["\']([a-zA-Z0-9_-]+)["\']', line)
            if match:
                deps.append({"name": match.group(1), "version": "unknown", "section": "dependencies"})

    elif pm_type == "go":
        for line in content.split("\n"):
            line = line.strip()
            if line and not line.startswith("require") and not line.startswith("go ") and not line.startswith("//"):
                parts = line.split()
                if len(parts) >= 2 and not parts[0].startswith("(") and not parts[0].startswith(")"):
                    deps.append({"name": parts[0], "version": parts[1], "section": "dependencies"})

    elif pm_type == "composer":
        try:
            data = json.loads(content)
            for section in ["require", "require-dev"]:
                if section in data:
                    for name, version in data[section].items():
                        deps.append({"name": name, "version": str(version), "section": section})
        except (json.JSONDecodeError, ValueError):
            pass

    elif pm_type == "cargo":
        import re
        for section_match in re.finditer(r'\[([^\]]+)\]', content):
            section = section_match.group(1)
            if section.startswith("dependencies"):
                start = section_match.end()
                end = content.find("[", start)
                if end == -1:
                    end = len(content)
                section_content = content[start:end]
                for dep_match in re.finditer(r'^([a-zA-Z0-9_-]+)\s*=\s*["{]([^"}]+)', section_content, re.MULTILINE):
                    deps.append({"name": dep_match.group(1), "version": dep_match.group(2).strip(), "section": section})

    return deps


def _identify_confusion_candidates(deps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Identify dependencies that could be vulnerable to dependency confusion."""
    candidates: list[dict[str, Any]] = []
    seen_names: set[str] = set()

    for dep in deps:
        name = dep.get("name", "")
        version = dep.get("version", "")

        if name in seen_names:
            continue
        seen_names.add(name)

        score = 0
        reasons: list[str] = []

        # Check for patterns that suggest internal packages
        for pattern in INTERNAL_PACKAGE_PATTERNS:
            if re.match(pattern, name, re.IGNORECASE):
                score += 2
                reasons.append(f"Name matches internal package pattern: {pattern}")
                break

        # Scoped packages (@org/package) without scope config
        if name.startswith("@") and "/" in name:
            scope = name.split("/")[0]
            if not dep.get("resolved_from_private", False):
                score += 1
                reasons.append(f"Scoped package '{scope}' may not be pinned to private registry")

        # Packages with very specific version numbers (suggesting internal)
        if re.match(r"^\d+\.\d+\.\d+-[a-zA-Z]+\.\d+$", version):
            score += 1
            reasons.append(f"Pre-release/internal version pattern: {version}")

        # Version 99.99.99 (dependency confusion attack version)
        if version == "99.99.99":
            score += 3
            reasons.append(f"Suspicious version 99.99.99 — typical dependency confusion attack version")

        # No version specified
        if version in ("*", "", "unknown"):
            score += 1
            reasons.append("No version pinned — allows automatic upgrade to any version")

        # Packages with names suggesting internal infrastructure
        infra_keywords = ["internal", "private", "backend", "frontend", "common", "utils", "lib", "sdk", "core", "platform", "shared", "config", "auth"]
        for kw in infra_keywords:
            if kw in name.lower().split("-") or kw in name.lower().split("_"):
                score += 1
                reasons.append(f"Name contains internal infrastructure keyword: '{kw}'")
                break

        if score >= 2:
            candidates.append({
                "name": name,
                "version": version,
                "section": dep.get("section", ""),
                "confidence_score": score,
                "reasons": reasons,
            })

    # Deduplicate and sort by score
    candidates.sort(key=lambda c: c["confidence_score"], reverse=True)
    return candidates


async def _check_npm_registry(package_name: str) -> bool:
    """Check if a package exists on the public npm registry."""
    import httpx as _httpx
    try:
        async with _httpx.AsyncClient() as client:
            r = await client.get(f"https://registry.npmjs.org/{package_name}", timeout=8)
            return r.status_code == 200
    except Exception:
        return False


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    console.print(f"\n[module][+] Dependency Confusion Scanner[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=10) as client:
        console.print(f"  Checking {len(PACKAGE_FILES)} package file paths...")
        fetch_tasks = [_fetch_package_file(url, path, client) for path in PACKAGE_FILES]
        fetch_results = await asyncio.gather(*fetch_tasks, return_exceptions=True)

        for fetch_result in fetch_results:
            if not isinstance(fetch_result, dict):
                continue

            path = fetch_result.get("path", "")
            pm_type = fetch_result.get("pm_type", "unknown")
            content = fetch_result.get("content", "")

            if not content:
                continue

            console.print(f"  Found: {path} ({pm_type})")

            # Extract dependencies
            deps = _extract_dependencies(content, pm_type)
            if not deps:
                continue

            console.print(f"    Found {len(deps)} dependencies")

            # Identify confusion candidates
            candidates = _identify_confusion_candidates(deps)
            if not candidates:
                continue

            console.print(f"    {len(candidates)} potential confusion candidates")

            # Check top candidates against public registry
            for candidate in candidates[:5]:
                name = candidate["name"]
                score = candidate["confidence_score"]
                reasons = candidate.get("reasons", [])

                if pm_type == "npm":
                    exists_public = await _check_npm_registry(name)
                    if exists_public:
                        severity = "critical" if score >= 4 else "high"
                        title = f"Dependency confusion risk: '{name}' (v{ candidate.get('version', '?') }) exists on public npm"
                        print_finding(title, severity, url)
                        findings.append({
                            "package": name,
                            "version": candidate.get("version"),
                            "pm_type": pm_type,
                            "score": score,
                            "reasons": reasons,
                            "exists_on_public": True,
                            "source_file": path,
                        })
                        if session:
                            await session.add_finding(
                                target=url, module="dep_confusion",
                                vuln_type="dependency_confusion",
                                severity=severity, confidence="confirmed",
                                title=title,
                                description=f"Dependency '{name}' ({pm_type}) from {path} exists on the public registry. If this is an internal package, an attacker can publish a higher version to the public registry and have it resolved instead of the intended internal package.",
                                evidence=f"Package: {name}@{candidate.get('version')}\nSource: {path}\nReasons: {'; '.join(reasons)}",
                                remediation="1. Scope all internal packages (e.g., @org/package). 2. Pin private registry in package manager config. 3. Use lockfiles with integrity hashes. 4. Block public registry fallback for scoped packages. 5. Register placeholder names for internal packages on public registries.",
                                cvss_score=9.1 if severity == "critical" else 7.5, cwe="CWE-1104",
                            )
                    else:
                        console.print(f"    [dim]{name} not found on public npm — likely internal[/dim]")

            # General finding: package file exposed
            title = f"Package dependency file exposed: {path} ({pm_type}, {len(deps)} dependencies)"
            print_finding(title, "medium", url)
            findings.append({
                "issue": "package_file_exposed",
                "path": path,
                "pm_type": pm_type,
                "dep_count": len(deps),
            })
            if session:
                await session.add_finding(
                    target=url, module="dep_confusion",
                    vuln_type="package_file_exposed",
                    severity="medium", confidence="confirmed",
                    title=title,
                    description=f"Package management file {path} ({pm_type}) is publicly accessible. This reveals the application's dependency tree, which attackers can analyze for vulnerable and internal packages.",
                    remediation="1. Block access to package management files via web server config. 2. Remove build artifacts from production servers. 3. Audit for exposed internal package names.",
                    cvss_score=5.3, cwe="CWE-200",
                )

    console.print(f"  Dependency confusion scan complete -- {len(findings)} issues")
    return {"target": url, "findings": findings, "count": len(findings)}
