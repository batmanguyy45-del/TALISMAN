"""Dependency confusion scanner — detects vulnerable dependency resolution patterns in package files."""
from __future__ import annotations
import asyncio
import json
import re
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console

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


async def _check_npm_registry(package_name: str, scope: Any) -> bool:
    """Check if a package exists on the public npm registry."""
    try:
        url = f"https://registry.npmjs.org/{package_name}"
        async with TalismanHTTPClient(timeout=8, scope=scope) as client:
            response = await client.get(url)
            return response.status_code == 200
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
    """Collect package-manifest observations and dependency-confusion candidates.

    A public package with a suspicious-looking name does not prove that the
    dependency is private, that the build uses public-registry fallback, or
    that an attacker can influence resolution. Public manifest availability is
    also not, by itself, a security vulnerability.
    """
    from urllib.parse import urlsplit

    url = target if "://" in target else f"https://{target}"
    if scope is None:
        return {
            "target": url,
            "findings": [],
            "candidates": [],
            "observations": [],
            "count": 0,
            "error": "scope_enforcer_required",
        }

    try:
        scope.assert_in_scope(url)
    except Exception as exc:
        return {
            "target": url,
            "findings": [],
            "candidates": [],
            "observations": [],
            "count": 0,
            "error": str(exc),
        }

    if urlsplit(url).scheme not in {"http", "https"}:
        return {
            "target": url,
            "findings": [],
            "candidates": [],
            "observations": [],
            "count": 0,
            "error": "invalid_target_scheme",
        }

    console.print(
        f"\\n[module][+] Dependency Confusion Assessment[/module] -> [target]{url}[/target]"
    )
    candidates_out: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    checked_registry_packages: set[str] = set()

    async with TalismanHTTPClient(proxy=proxy, timeout=10, scope=scope) as client:
        console.print(f"  Checking {len(PACKAGE_FILES)} common package manifest paths...")
        fetch_tasks = [_fetch_package_file(url, path, client) for path in PACKAGE_FILES]
        fetch_results = await asyncio.gather(*fetch_tasks, return_exceptions=True)

        for fetch_result in fetch_results:
            if not isinstance(fetch_result, dict):
                continue

            path = str(fetch_result.get("path", ""))
            pm_type = str(fetch_result.get("pm_type", "unknown"))
            content = fetch_result.get("content", "")
            if not isinstance(content, str) or not content:
                continue

            deps = _extract_dependencies(content, pm_type)
            observation = {
                "type": "public_dependency_manifest",
                "path": path,
                "package_manager": pm_type,
                "dependency_count": len(deps),
                "note": (
                    "Manifest exposure is recorded as an observation only; "
                    "public package manifests are often intentional and do not "
                    "demonstrate a confidentiality or supply-chain vulnerability."
                ),
            }
            observations.append(observation)
            console.print(
                f"  Observed {path}: {pm_type}, {len(deps)} dependencies "
                "(not automatically reportable)"
            )

            if not deps:
                continue

            for candidate in _identify_confusion_candidates(deps)[:10]:
                package_name = candidate.get("name", "")
                if not isinstance(package_name, str) or not package_name:
                    continue
                if pm_type != "npm" or package_name in checked_registry_packages:
                    continue
                checked_registry_packages.add(package_name)

                exists_public = await _check_npm_registry(package_name, scope)
                if not exists_public:
                    continue

                candidate_record = {
                    "type": "potential_dependency_namespace_collision",
                    "package": package_name,
                    "declared_version": candidate.get("version"),
                    "package_manager": pm_type,
                    "source_file": path,
                    "heuristic_score": candidate.get("confidence_score", 0),
                    "heuristic_reasons": candidate.get("reasons", []),
                    "exists_on_public_registry": True,
                    "confidence": "candidate",
                    "requires_verification": [
                        "Confirm the package name is reserved for or owned by the target organization.",
                        "Inspect the actual build and package-manager registry configuration.",
                        "Prove that dependency resolution can fall back to the public registry.",
                        "Verify that lockfiles, namespace controls, and integrity pinning do not prevent substitution.",
                    ],
                    "safety_note": (
                        "Do not publish or install a substitute package to test this. "
                        "Establish the resolution path using configuration and an isolated local fixture."
                    ),
                }
                candidates_out.append(candidate_record)
                console.print(
                    f"  Candidate only: {package_name} exists on the public npm registry; "
                    "ownership and resolver behavior remain unproven"
                )

    console.print(
        f"  Assessment complete — {len(candidates_out)} dependency-confusion candidates, "
        f"{len(observations)} public-manifest observations"
    )
    return {
        "target": url,
        "findings": [],
        "candidates": candidates_out,
        "observations": observations,
        "count": 0,
        "candidate_count": len(candidates_out),
        "observation_count": len(observations),
    }
