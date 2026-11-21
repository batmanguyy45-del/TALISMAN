"""Redact credential-like material before persistence, logs, or report output."""
from __future__ import annotations

import re
from typing import Any

MAX_REDACTION_INPUT_CHARS = 2_000_000

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"(?im)(\bauthorization\s*:\s*(?:bearer|basic)\s+)[^\s,;]+"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?im)(\b(?:proxy-authorization)\s*:\s*)[^\r\n]+"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?im)(\b(?:cookie|set-cookie)\s*:\s*)[^\r\n]+"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)([?&](?:access_token|refresh_token|id_token|client_secret|api[_-]?key|apikey|secret|password|passwd|token|jwt|session)=)[^&#\s]+"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"""(?i)((?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|secret|password|passwd|pwd|token|jwt)\s*[=:]\s*["']?)[^"'\s&,;]+"""
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)((?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^:/\s]+:)[^@/\s]+(@)"),
        r"\1[REDACTED]\2",
    ),
    (
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            re.IGNORECASE,
        ),
        "[PRIVATE KEY REDACTED]",
    ),
    (
        re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----", re.IGNORECASE),
        "[PGP PRIVATE KEY REDACTED]",
    ),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[AWS_ACCESS_KEY_REDACTED]"),
    (re.compile(r"\b(?:ghp|ghs|ghu)_[A-Za-z0-9]{30,}\b"), "[GITHUB_TOKEN_REDACTED]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"), "[GITHUB_TOKEN_REDACTED]"),
    (re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "[SLACK_TOKEN_REDACTED]"),
    (re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"), "[STRIPE_SECRET_REDACTED]"),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), "[ANTHROPIC_KEY_REDACTED]"),
    (re.compile(r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{30,}\b"), "[SENDGRID_KEY_REDACTED]"),
    (re.compile(r"\bwhsec_[A-Za-z0-9]{24,}\b"), "[WEBHOOK_SECRET_REDACTED]"),
    (re.compile(r"\bya29\.[A-Za-z0-9_-]{20,}\b"), "[OAUTH_TOKEN_REDACTED]"),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "[JWT_REDACTED]",
    ),
)


def redact_sensitive_text(value: str, *, max_chars: int = MAX_REDACTION_INPUT_CHARS) -> str:
    """Redact common secret formats and credential-bearing headers/URLs.

    The function intentionally favors preventing credential disclosure over
    preserving exact request bytes. It is suitable for evidence and reports,
    not for replayable raw network captures.
    """
    if not isinstance(value, str):
        return str(value)

    truncated = len(value) > max_chars
    text = value[:max_chars] if truncated else value

    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)

    if truncated:
        text += "\n[TRUNCATED: redaction input exceeded configured size limit]"
    return text


def redact_sensitive_value(value: Any, *, depth: int = 0) -> Any:
    """Recursively redact string values in JSON-like evidence structures."""
    if depth > 12:
        return "[MAX_DEPTH]"
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, list):
        return [redact_sensitive_value(item, depth=depth + 1) for item in value[:1000]]
    if isinstance(value, tuple):
        return tuple(redact_sensitive_value(item, depth=depth + 1) for item in value[:1000])
    if isinstance(value, dict):
        return {
            str(key)[:200]: redact_sensitive_value(item, depth=depth + 1)
            for key, item in list(value.items())[:1000]
        }
    return value
