"""LFI / Path Traversal / PHP Wrapper scanner."""
from __future__ import annotations
import asyncio
import base64
import urllib.parse
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.payload_engine import LFI_PAYLOADS
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

LFI_CONFIRM_STRINGS = [
    "root:x:0:0", "root:!:", "daemon:", "bin:", "nobody:",   # /etc/passwd
    "[extensions]", "; for 16-bit app support",              # win.ini
    "\\WINDOWS", "Microsoft Windows",                         # Windows files
    "DOCUMENT_ROOT", "HTTP_HOST", "PATH=",                   # /proc/self/environ
    "Linux version", "BOOT_IMAGE",                           # /proc/version
    "<?php",                                                  # PHP source disclosure
    "DB_PASSWORD", "SECRET_KEY", "DATABASE_URL",             # .env files
    "define('DB_", "define('AUTH_KEY",                       # wp-config.php
]

LFI_PARAMS = [
    "file", "page", "path", "include", "template", "view",
    "doc", "document", "folder", "root", "dir", "content",
    "f", "p", "pg", "style", "pdf", "download", "read",
    "load", "show", "get", "data", "menu", "lang", "language",
]


async def _test_lfi(
    url: str, param: str, client: TalismanHTTPClient
) -> dict[str, Any] | None:
    parsed = urllib.parse.urlparse(url)
    base_params = dict(urllib.parse.parse_qsl(parsed.query))

    all_payloads = (
        LFI_PAYLOADS["unix"]
        + LFI_PAYLOADS["windows"]
        + LFI_PAYLOADS["bypass_encoding"]
        + LFI_PAYLOADS["wrapper_php"]
    )

    for payload in all_payloads:
        try:
            test_params = {**base_params, param: payload}
            test_url = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
            r = await client.get(test_url)
            resp_text = r.text

            # Check for PHP base64 filter output — decode and check
            if "php://filter" in payload and r.status_code == 200:
                import re
                b64_match = re.search(r'([A-Za-z0-9+/]{40,}={0,2})', resp_text)
                if b64_match:
                    try:
                        decoded = base64.b64decode(b64_match.group(1)).decode("utf-8", errors="ignore")
                        if "<?php" in decoded or "root:x:" in decoded:
                            return {
                                "param": param,
                                "payload": payload,
                                "technique": "php_filter_b64",
                                "evidence": f"PHP source disclosed via filter: {decoded[:200]}",
                                "request": f"GET {test_url} HTTP/1.1",
                            }
                    except Exception:
                        pass

            for indicator in LFI_CONFIRM_STRINGS:
                if indicator in resp_text:
                    return {
                        "param": param,
                        "payload": payload,
                        "technique": "direct",
                        "indicator": indicator,
                        "evidence": resp_text[:300],
                        "request": f"GET {test_url} HTTP/1.1",
                    }
        except Exception:
            pass
    return None


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    console.print(f"\n[module]⚡ LFI / Path Traversal Scanner[/module] → [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    parsed = urllib.parse.urlparse(url)
    existing_params = list(dict(urllib.parse.parse_qsl(parsed.query)).keys())
    params = list(set(existing_params + LFI_PARAMS))

    async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
        tasks = [_test_lfi(url, p, client) for p in params]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, dict):
                severity = "high"
                title = f"LFI / Path Traversal — param '{result['param']}'"
                print_finding(title, severity, url)
                findings.append(result)
                if session:
                    await session.add_finding(
                        target=url, module="lfi", vuln_type="lfi",
                        severity=severity, confidence="confirmed",
                        title=title,
                        description=(
                            f"Local File Inclusion via parameter '{result['param']}'. "
                            f"Payload '{result['payload']}' read files from the filesystem. "
                            f"Indicator: {result.get('indicator', result.get('technique', ''))}"
                        ),
                        request=result["request"],
                        evidence=result.get("evidence", ""),
                        reproduction=f"GET {url}?{result['param']}={urllib.parse.quote(result['payload'])}",
                        remediation=(
                            "1. Never use user input to construct file paths.\n"
                            "2. Use a whitelist of allowed file names/paths.\n"
                            "3. Resolve canonical paths and validate they are within the expected base directory.\n"
                            "4. Disable dangerous PHP wrappers (allow_url_include=Off)."
                        ),
                        cvss_score=7.5, cwe="CWE-22",
                        references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion"],
                    )

    console.print(f"  Found {len(findings)} LFI vulnerabilities")
    return {"target": url, "findings": findings, "count": len(findings)}
