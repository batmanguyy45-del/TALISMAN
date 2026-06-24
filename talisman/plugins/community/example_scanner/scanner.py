"""Example scanner plugin — checks for missing X-Content-Type-Options header."""
from __future__ import annotations
from typing import Any, AsyncGenerator
from talisman.plugins.base import ScannerPlugin, Finding


class ExampleScannerPlugin(ScannerPlugin):
    name = "example-scanner"
    version = "1.0.0"
    description = "Checks for missing X-Content-Type-Options security header"
    vuln_class = "missing-security-header"
    tags = ["example", "header", "security"]

    async def check(
        self,
        target: str,
        session_context: dict[str, Any],
        http_client: Any,
        config: dict[str, Any],
    ) -> AsyncGenerator[Finding, None]:
        response = await http_client.get(target)
        xcto = response.headers.get("X-Content-Type-Options", "")
        if "nosniff" not in xcto.lower():
            yield Finding(
                title="Missing X-Content-Type-Options Header",
                severity="medium",
                confidence="firm",
                vuln_type="missing_security_header",
                target=target,
                description=(
                    "The X-Content-Type-Options header is missing or set incorrectly. "
                    "Without this header, older browsers may perform MIME-type sniffing, "
                    "which can lead to XSS attacks."
                ),
                evidence=f"X-Content-Type-Options: {xcto or '(not set)'}",
                reproduction=f"curl -I {target}",
                remediation=(
                    "Set the X-Content-Type-Options header to 'nosniff' on all responses."
                ),
                cvss_score=5.0,
                cwe="CWE-16",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
            )
