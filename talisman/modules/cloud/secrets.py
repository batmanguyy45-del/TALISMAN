"""Secret discovery with redacted, non-promotional evidence.

Pattern matches are candidates only. A token-shaped string can be a placeholder,
test credential, revoked credential, public identifier, or a false positive.
TALISMAN never stores the raw candidate value in its session database or logs.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import console, get_logger

log = get_logger(__name__)

# Only formats that are plausibly secret credentials are listed here.
# Publishable identifiers (for example Stripe pk_* keys) and unstructured
# UUIDs are intentionally excluded.
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}"), "high"),
    (
        "AWS Secret Access Key",
        re.compile(r"(?i)aws.{0,20}(['\"])[0-9a-zA-Z/+]{40}\1"),
        "high",
    ),
    ("Google OAuth Access Token", re.compile(r"ya29\.[0-9A-Za-z_-]{20,}"), "high"),
    (
        "GCP Service Account Key",
        re.compile(r'"type"\s*:\s*"service_account"'),
        "high",
    ),
    ("GitHub Personal Access Token", re.compile(r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}"), "high"),
    ("GitHub App Token", re.compile(r"ghs_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}"), "high"),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"), "high"),
    (
        "Slack Webhook URL",
        re.compile(r"https://hooks\.slack\.com/services/[A-Z0-9]{9}/[A-Z0-9]{11}/[a-zA-Z0-9]{24}"),
        "high",
    ),
    ("Stripe Secret Key", re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{24,}"), "high"),
    ("Stripe Webhook Signing Secret", re.compile(r"whsec_[0-9a-zA-Z]{32,}"), "high"),
    ("SendGrid API Key", re.compile(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"), "high"),
    ("Twilio Account SID", re.compile(r"AC[a-z0-9]{32}"), "medium"),
    ("OpenAI API Key", re.compile(r"sk-[A-Za-z0-9]{48}"), "high"),
    ("Anthropic API Key", re.compile(r"sk-ant-[A-Za-z0-9_-]{90,}"), "high"),
    ("Mailgun API Key", re.compile(r"key-[0-9a-zA-Z]{32}"), "high"),
    ("Firebase Server Key", re.compile(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"), "high"),
    (
        "JWT",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}"),
        "medium",
    ),
    (
        "URL with embedded credentials",
        re.compile(r"https?://[^:/\s]+:[^@/\s]+@[^/\s]+"),
        "high",
    ),
    ("RSA/PKCS8 Private Key Header", re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----"), "high"),
    ("EC Private Key Header", re.compile(r"-----BEGIN EC PRIVATE KEY-----"), "high"),
    ("OpenSSH Private Key Header", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"), "high"),
    ("PGP Private Key Header", re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"), "high"),
    (
        "PostgreSQL Connection URL",
        re.compile(r"postgres(?:ql)?://[^:\s]+:[^@\s]+@[^/\s]+/\S+", re.IGNORECASE),
        "high",
    ),
    (
        "MySQL Connection URL",
        re.compile(r"mysql://[^:\s]+:[^@\s]+@[^/\s]+/\S+", re.IGNORECASE),
        "high",
    ),
    (
        "MongoDB Connection URL",
        re.compile(r"mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@[^/\s]+", re.IGNORECASE),
        "high",
    ),
    (
        "Redis Connection URL",
        re.compile(r"redis://:[^@\s]+@[^/\s]+", re.IGNORECASE),
        "high",
    ),
    (
        "Azure Storage Account Key",
        re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+"),
        "high",
    ),
    (
        "Datadog API Key",
        re.compile(r"(?i)datadog.{0,20}([a-zA-Z0-9]{40})"),
        "medium",
    ),
    (
        "Generic Password Assignment",
        re.compile(r"""(?i)(?:password|passwd|pwd)\s*[=:]\s*['"]([^'"]{8,})['"]"""),
        "low",
    ),
    (
        "Generic API Key Assignment",
        re.compile(r"""(?i)api[_-]?key\s*[=:]\s*['"]([a-zA-Z0-9_-]{16,})['"]"""),
        "low",
    ),
    (
        "Generic Secret Assignment",
        re.compile(r"""(?i)secret\s*[=:]\s*['"]([a-zA-Z0-9_-]{16,})['"]"""),
        "low",
    ),
]

SENSITIVE_FILES = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.backup",
    "/.env.old",
    "/.env.example",
    "/.env.development",
    "/config.json",
    "/config.yml",
    "/config.yaml",
    "/appsettings.json",
    "/appsettings.Development.json",
    "/secrets.json",
    "/credentials.json",
    "/.aws/credentials",
    "/.aws/config",
    "/wp-config.php",
    "/configuration.php",
    "/settings.py",
    "/local_settings.py",
    "/database.yml",
    "/storage.yml",
    "/.git/config",
]

_PLACEHOLDER_VALUES = (
    "example",
    "changeme",
    "change_me",
    "your_",
    "your-",
    "placeholder",
    "dummy",
    "redacted",
    "replace_me",
    "replace-this",
    "not-a-real",
    "xxxx",
    "sample",
)


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().lower()
    return (
        not normalized
        or normalized in {"null", "none", "undefined"}
        or any(marker in normalized for marker in _PLACEHOLDER_VALUES)
    )


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:20]


async def _scan_content(content: str, source: str) -> list[dict[str, Any]]:
    """Return redacted pattern-match candidates; never return credential material."""
    found: list[dict[str, Any]] = []
    seen: set[str] = set()

    for name, pattern, severity_hint in SECRET_PATTERNS:
        for match in pattern.finditer(content):
            raw_value = match.group(0)
            if _is_placeholder(raw_value):
                continue

            fingerprint = _fingerprint(raw_value)
            key = f"{name}:{fingerprint}"
            if key in seen:
                continue
            seen.add(key)

            line_number = content.count("\n", 0, match.start()) + 1
            found.append(
                {
                    "type": name,
                    "severity_hint": severity_hint,
                    "confidence": "candidate",
                    "value": "[REDACTED]",
                    "fingerprint": fingerprint,
                    "source": source,
                    "line": line_number,
                    "requires_credential_validation": True,
                    "verification_required": (
                        "Determine whether this is a real secret rather than a "
                        "placeholder, public identifier, test value, revoked token, "
                        "or false positive. Validate only through the provider's "
                        "non-invasive metadata/status endpoint where permitted; "
                        "never use the credential to access user data."
                    ),
                }
            )

    return found


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    if scope is None:
        return {
            "target": url,
            "secrets": [],
            "candidates": [],
            "observations": [],
            "count": 0,
            "error": "scope_enforcer_required",
        }

    try:
        scope.assert_in_scope(url)
    except ScopeViolationError as exc:
        return {
            "target": url,
            "secrets": [],
            "candidates": [],
            "observations": [],
            "count": 0,
            "error": str(exc),
        }

    console.print(f"\n[module][+] Redacted Secret Discovery[/module] -> [target]{url}[/target]")
    candidates: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []

    async with TalismanHTTPClient(
        proxy=proxy,
        timeout=15,
        verify_ssl=True,
        follow_redirects=False,
        scope=scope,
    ) as client:
        try:
            response = await client.get(url)
            candidates.extend(await _scan_content(response.text, "main_page"))
            js_urls = re.findall(
                r"""src=["']([^"']+\.js(?:\?[^"']*)?)["']""",
                response.text,
                re.IGNORECASE,
            )
        except Exception as exc:
            log.debug("secret_scan_main_page_failed", error=type(exc).__name__)
            js_urls = []

        for js_path in js_urls[:20]:
            js_url = (
                js_path
                if js_path.startswith(("http://", "https://"))
                else url.rstrip("/") + "/" + js_path.lstrip("/")
            )
            try:
                js_response = await client.get(js_url, timeout=10)
                if js_response.status_code == 200:
                    candidates.extend(
                        await _scan_content(js_response.text, f"js:{js_path[:200]}")
                    )
            except Exception as exc:
                log.debug("secret_scan_js_failed", error=type(exc).__name__)

        for path in SENSITIVE_FILES:
            try:
                file_response = await client.get(url.rstrip("/") + path, timeout=8)
                if file_response.status_code != 200 or len(file_response.content) <= 10:
                    continue

                file_candidates = await _scan_content(
                    file_response.text,
                    f"file:{path}",
                )
                candidates.extend(file_candidates)
                if not file_candidates:
                    observations.append(
                        {
                            "type": "sensitive_path_responded",
                            "path": path,
                            "status": file_response.status_code,
                            "bytes": len(file_response.content),
                            "classification": "observation",
                            "note": (
                                "HTTP 200 on a conventional configuration path "
                                "does not prove sensitive disclosure. Inspect the "
                                "file's content and deployment intent."
                            ),
                        }
                    )
            except Exception as exc:
                log.debug("secret_scan_path_failed", path=path, error=type(exc).__name__)

    unique: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        unique.setdefault(
            f"{candidate['type']}:{candidate['fingerprint']}",
            candidate,
        )
    candidates = list(unique.values())

    console.print(
        f" Secret discovery complete — {len(candidates)} redacted candidates, "
        f"{len(observations)} path observations; no credentials stored"
    )

    return {
        "target": url,
        "secrets": candidates,
        "candidates": candidates,
        "observations": observations,
        "findings": [],
        "count": 0,
        "candidate_count": len(candidates),
        "observation_count": len(observations),
        "raw_secret_values_persisted": False,
    }
