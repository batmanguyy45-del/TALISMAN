"""Git/Backup/VCS exposure scanner — detects exposed .git, .env, configuration files, and backup artifacts."""
from __future__ import annotations
import asyncio
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

EXPOSURE_PATHS = [
    # Version control
    "/.git/HEAD",
    "/.git/config",
    "/.git/index",
    "/.git/refs/heads/master",
    "/.git/refs/heads/main",
    "/.git/logs/HEAD",
    "/.svn/entries",
    "/.svn/wc.db",
    "/.hg/requires",
    "/.hg/store/00manifest.i",
    "/.bzr/README",
    # Environment / config
    "/.env",
    "/.env.example",
    "/.env.production",
    "/.env.local",
    "/.env.dev",
    "/.env.staging",
    "/env",
    "/config.json",
    "/config.php",
    "/configuration.php",
    "/settings.py",
    "/appsettings.json",
    # IDE / editor
    "/.vscode/settings.json",
    "/.idea/workspace.xml",
    "/.idea/modules.xml",
    "/*.sublime-project",
    # CI/CD
    "/.github/workflows/main.yml",
    "/.gitlab-ci.yml",
    "/.circleci/config.yml",
    "/Jenkinsfile",
    "/.travis.yml",
    "/bitbucket-pipelines.yml",
    # Backup / temp files
    "/backup",
    "/backup.zip",
    "/backup.tar.gz",
    "/dump.sql",
    "/database.sql",
    "/db_backup.sql",
    "/*.bak",
    "/*.old",
    "/*.swp",
    "/*~",
    # Code quality
    "/.coveralls.yml",
    "/.codeclimate.yml",
    "/phpunit.xml",
    "/jest.config.js",
    # Container
    "/Dockerfile",
    "/docker-compose.yml",
    "/docker-compose.yaml",
    "/.dockerignore",
    # Package files
    "/package.json",
    "/package-lock.json",
    "/requirements.txt",
    "/Pipfile",
    "/Gemfile",
    "/Gemfile.lock",
    "/composer.json",
    "/composer.lock",
    "/go.mod",
    "/go.sum",
    "/Cargo.toml",
    "/Cargo.lock",
    # Cloud
    "/.aws/config",
    "/.aws/credentials",
    "/credentials.json",
    "/service-account.json",
    "/.gcloud/config.json",
    # API / tokens
    "/.npmrc",
    "/.yarnrc",
    "/.gem/credentials",
    "/.pypirc",
    "/netrc",
    "/.netrc",
    # SSH
    "/.ssh/id_rsa",
    "/.ssh/id_rsa.pub",
    "/.ssh/authorized_keys",
    "/.ssh/config",
    "/id_rsa",
    # Common web roots
    "/admin/backup",
    "/private",
    "/protected",
    "/internal",
    "/temp",
    "/tmp",
    "/logs",
    "/log",
    "/error_log",
    "/access_log",
]

GIT_HEAD_PATTERNS = [b"ref: refs/heads/", b"ref:"]
GIT_CONFIG_SIGNATURES = [b"[core]", b"[remote", b"[branch"]


async def _test_path(
    url: str, path: str, client: TalismanHTTPClient,
) -> dict[str, Any] | None:
    """Test a single path for exposure."""
    test_url = url.rstrip("/") + path
    try:
        r = await client.get(test_url, timeout=8)
        if r.status_code == 200 and len(r.content) > 0:
            content_preview = r.content[:500]
            content_lower = r.text.lower()[:500]

            # Determine the type of exposure
            exposure_type = "unknown"
            sensitive = False

            # .git detection
            if "/.git/head" in path.lower() or "/.git/config" in path.lower():
                if any(p in content_preview for p in GIT_HEAD_PATTERNS + GIT_CONFIG_SIGNATURES):
                    exposure_type = "git_exposure"
                    sensitive = True

            # .env detection
            elif path.endswith(".env") or path.endswith("env"):
                if any(k in content_lower for k in ["api_key", "secret", "password", "database_url", "db_host", "aws_", "access_key", "token"]):
                    exposure_type = "env_exposure"
                    sensitive = True
                elif "=" in content_preview.decode("utf-8", errors="replace") and len(content_preview) > 20:
                    exposure_type = "env_exposure"
                    sensitive = True

            # SSH key detection
            elif "id_rsa" in path or ".ssh" in path:
                if b"PRIVATE KEY" in content_preview or b"ssh-rsa" in content_preview or b"ssh-ed25519" in content_preview:
                    exposure_type = "ssh_exposure"
                    sensitive = True

            # Database dump detection
            elif path.endswith(".sql") or "dump" in path.lower() or "backup" in path.lower():
                if any(k in content_lower for k in ["insert into", "create table", "drop table", "database:", "--"]):
                    exposure_type = "database_exposure"
                    sensitive = True

            # CI/CD config
            elif any(k in path.lower() for k in [".github", ".gitlab", ".circleci", "jenkinsfile", ".travis"]):
                if any(k in content_lower for k in ["api_key", "secret", "token", "password", "aws_", "DOCKER_"]):
                    exposure_type = "cicd_exposure"
                    sensitive = True

            # Container config
            elif "dockerfile" in path.lower() or "docker-compose" in path.lower():
                exposure_type = "container_config"
                sensitive = "from " in content_lower or "image:" in content_lower or "services:" in content_lower

            # AWS/GCloud credentials
            elif "credentials.json" in path or "service-account" in path:
                if '"type":' in content_lower and "project_id" in content_lower:
                    exposure_type = "cloud_credentials"
                    sensitive = True

            # General sensitive exposure
            elif any(k in content_lower for k in [
                "secret", "password", "api_key", "api key", "access_token",
                "private key", "-----begin", "oauth", "jwt_secret",
            ]):
                exposure_type = "sensitive_exposure"
                sensitive = True

            return {
                "path": path,
                "status": r.status_code,
                "size": len(r.content),
                "type": exposure_type,
                "sensitive": sensitive,
                "evidence": r.text[:400],
            }
    except Exception:
        pass
    return None


async def _test_git_smuggling(
    url: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test for .git directory listing and common git objects."""
    findings: list[dict[str, Any]] = []
    git_paths = [
        "/.git/",
        "/.git/objects/",
        "/.git/objects/pack/",
        "/.git/refs/",
        "/.git/HEAD",
    ]

    for path in git_paths:
        result = await _test_path(url, path, client)
        if result:
            findings.append(result)

    # If .git/HEAD exists, try to read common objects
    # Check for directory listing on /.git/
    try:
        r = await client.get(url.rstrip("/") + "/.git/", timeout=8)
        if r.status_code == 200 and ("index of" in r.text.lower() or "HEAD" in r.text):
            findings.append({
                "path": "/.git/",
                "status": 200,
                "type": "git_directory_listing",
                "sensitive": True,
                "evidence": r.text[:400],
            })
    except Exception:
        pass

    return findings


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    console.print(f"\n[module][+] Git/Backup/VCS Exposure Scanner[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=8) as client:
        console.print(f"  Testing {len(EXPOSURE_PATHS)} sensitive paths...")
        path_tasks = [_test_path(url, path, client) for path in EXPOSURE_PATHS]
        results = await asyncio.gather(*path_tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, dict) and result.get("path"):
                exposure_type = result.get("type", "unknown")
                path = result.get("path", "")
                sensitive = result.get("sensitive", False)

                if exposure_type == "git_exposure":
                    severity = "critical"
                    title = f"Git repository exposed: {path}"
                elif exposure_type == "env_exposure":
                    severity = "critical"
                    title = f"Environment file exposed: {path}"
                elif exposure_type == "ssh_exposure":
                    severity = "critical"
                    title = f"SSH private key exposed: {path}"
                elif exposure_type == "cloud_credentials":
                    severity = "critical"
                    title = f"Cloud credentials exposed: {path}"
                elif exposure_type == "database_exposure":
                    severity = "critical"
                    title = f"Database backup exposed: {path}"
                elif exposure_type == "sensitive_exposure":
                    severity = "high"
                    title = f"Sensitive file exposed: {path}"
                elif exposure_type == "cicd_exposure":
                    severity = "high"
                    title = f"CI/CD config exposed: {path}"
                elif exposure_type == "container_config":
                    severity = "medium"
                    title = f"Container configuration exposed: {path}"
                else:
                    severity = "medium" if result.get("size", 0) > 100 else "low"
                    title = f"File exposure: {path}"

                print_finding(title, severity, url)
                findings.append(result)

                if session and sensitive:
                    await session.add_finding(
                        target=url, module="git_exposure",
                        vuln_type=exposure_type,
                        severity=severity, confidence="confirmed",
                        title=title,
                        description=f"Sensitive file exposed at {path} ({result.get('size', 0)} bytes, HTTP {result.get('status')}). This file contains confidential information that should never be publicly accessible.",
                        evidence=result.get("evidence", ""),
                        remediation="1. Remove exposed files from the webroot. 2. Configure web server to deny access to hidden files and directories. 3. Use .htaccess / nginx rules to block /.git and similar paths. 4. Review git history for committed secrets.",
                        cvss_score={
                            "critical": 9.1, "high": 7.5, "medium": 5.3, "low": 3.7,
                        }.get(severity, 5.0),
                        cwe="CWE-540",
                    )

    console.print(f"  Exposure scan complete -- {len(findings)} issues")
    return {"target": url, "findings": findings, "count": len(findings)}
