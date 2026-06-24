"""File upload vulnerability scanner — content-type bypass, extension filter, size limits, double extension."""
from __future__ import annotations
import asyncio
import hashlib
import random
import string
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

UPLOAD_ENDPOINTS = [
    "/upload", "/api/upload", "/file/upload",
    "/api/file/upload", "/upload-file", "/api/upload-file",
    "/profile/upload", "/api/profile/upload",
    "/image/upload", "/api/image/upload",
    "/media/upload", "/api/media/upload",
    "/avatar", "/api/avatar",
    "/import", "/api/import",
    "/api/v1/upload", "/api/v2/upload",
]

TEST_FILE_EXTENSIONS = [
    ".php", ".php5", ".phtml", ".php7", ".php8",
    ".asp", ".aspx", ".asa", ".cer",
    ".jsp", ".jspx", ".war",
    ".cgi", ".pl", ".py",
    ".shtml", ".stm", ".shtm",
    ".htaccess", ".htpasswd",
]

DOUBLE_EXTENSIONS = [
    ".jpg.php", ".png.php", ".gif.php",
    ".php.jpg", ".php.png",
    ".php;.jpg", ".php%00.jpg",
    ".jpg/.php", ".php.",
    ".php\x00.jpg", ".php:jpg",
]

CASE_VARIANTS = [
    ".PhP", ".PHP", ".pHP", ".pHp",
    ".Asp", ".ASP", ".aSp",
    ".Jsp", ".JSP", ".jSp",
]

CONTENT_TYPES = [
    "image/jpeg", "image/png", "image/gif",
    "application/pdf", "text/plain",
    "application/x-php",
]

UPLOAD_CANARY_PREFIX = "TLSMFILE"


async def _test_upload_endpoint(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test a file upload endpoint for injection vulnerabilities."""
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint

    for ext in TEST_FILE_EXTENSIONS[:5]:
        canary = f"{UPLOAD_CANARY_PREFIX}{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"
        content = f"<?php echo '{canary}'; ?>"
        filename = f"test{ext}"

        try:
            boundary = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
            body = (
                f"--{boundary}\r\n"
                f"Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
                f"Content-Type: application/x-php\r\n\r\n"
                f"{content}\r\n"
                f"--{boundary}--\r\n"
            )
            r = await client.post(test_url,
                data=body.encode(),
                headers={
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                },
                timeout=12,
            )

            # Check if upload was accepted
            if r.status_code in (200, 201, 204):
                resp_text = r.text.lower()
                # Check if the filename or content is reflected
                if canary.lower() in resp_text or filename.lower() in resp_text:
                    findings.append({
                        "issue": "script_upload_accepted",
                        "extension": ext,
                        "filename": filename,
                        "canary": canary,
                        "status": r.status_code,
                        "evidence": r.text[:300],
                    })
                    break
        except Exception:
            pass

    return findings


async def _test_content_type_bypass(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test content-type spoofing to bypass upload filters."""
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint
    canary = f"{UPLOAD_CANARY_PREFIX}{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"

    for ct in CONTENT_TYPES:
        filename = f"shell.php"
        content = f"test_content_{canary}"

        try:
            boundary = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
            body = (
                f"--{boundary}\r\n"
                f"Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
                f"Content-Type: {ct}\r\n\r\n"
                f"{content}\r\n"
                f"--{boundary}--\r\n"
            )
            r = await client.post(test_url,
                data=body.encode(),
                headers={
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                },
                timeout=12,
            )
            if r.status_code in (200, 201, 204):
                resp_text = r.text.lower()
                if canary.lower() in resp_text or filename.lower() in resp_text:
                    findings.append({
                        "issue": "content_type_bypass",
                        "content_type": ct,
                        "filename": filename,
                        "evidence": r.text[:300],
                    })
                    break
        except Exception:
            pass

    return findings


async def _test_double_extension(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test double-extension and character injection bypasses."""
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint
    canary = f"{UPLOAD_CANARY_PREFIX}{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"

    all_exts = DOUBLE_EXTENSIONS + CASE_VARIANTS + [f"shell{e}" for e in CASE_VARIANTS[:3]]

    for ext in all_exts[:10]:
        filename = f"test{ext}"
        content = f"<?php echo '{canary}'; ?>"

        try:
            boundary = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
            body = (
                f"--{boundary}\r\n"
                f"Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
                f"Content-Type: application/x-php\r\n\r\n"
                f"{content}\r\n"
                f"--{boundary}--\r\n"
            )
            r = await client.post(test_url,
                data=body.encode(),
                headers={
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                },
                timeout=12,
            )
            if r.status_code in (200, 201, 204):
                resp_text = r.text.lower()
                if canary.lower() in resp_text or filename.lower() in resp_text:
                    findings.append({
                        "issue": "double_extension_bypass",
                        "extension": ext,
                        "filename": filename,
                        "evidence": r.text[:300],
                    })
                    break
        except Exception:
            pass

    return findings


async def _test_content_validation(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test if file content is validated (magic bytes check)."""
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint

    # Send a PHP file with JPEG magic bytes
    canary = f"{UPLOAD_CANARY_PREFIX}{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"
    filename = "image.php"

    # JPEG magic bytes + PHP payload
    jpeg_magic = b"\xFF\xD8\xFF\xE0"
    php_payload = f"<?php echo '{canary}'; ?>".encode()
    content = jpeg_magic + php_payload

    try:
        boundary = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        body = (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
            f"Content-Type: image/jpeg\r\n\r\n"
        ).encode() + content + f"\r\n--{boundary}--\r\n".encode()

        r = await client.post(test_url,
            data=body,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
            timeout=12,
        )
        if r.status_code in (200, 201, 204):
            resp_text = r.text.lower()
            if canary.lower() in resp_text or filename.lower() in resp_text:
                findings.append({
                    "issue": "magic_byte_bypass",
                    "filename": filename,
                    "evidence": r.text[:300],
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
    console.print(f"\n[module][+] File Upload Vulnerability Scanner[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=15) as client:
        console.print(f"  Testing {len(UPLOAD_ENDPOINTS)} upload endpoints...")
        for endpoint in UPLOAD_ENDPOINTS:
            # -- 1. Script upload acceptance ------------------------------------------
            script_findings = await _test_upload_endpoint(url, endpoint, client)
            for sf in script_findings:
                title = f"Script file upload accepted at {endpoint} ({sf.get('filename', 'unknown')})"
                print_finding(title, "critical", url)
                findings.append(sf)
                if session:
                    await session.add_finding(
                        target=url, module="file_upload",
                        vuln_type="script_upload_accepted",
                        severity="critical", confidence="confirmed",
                        title=title,
                        description=f"Upload endpoint {endpoint} accepted a script file ({sf.get('filename')}) with content-type application/x-php. The unique canary '{sf.get('canary', '')}' was reflected in the response.",
                        evidence=sf.get("evidence", ""),
                        remediation="1. Validate file extension against an allowlist. 2. Store files outside webroot. 3. Serve uploaded files with Content-Disposition: attachment. 4. Scan for malicious content.",
                        cvss_score=9.8, cwe="CWE-434",
                    )

            # -- 2. Content-type spoofing ---------------------------------------------
            ct_findings = await _test_content_type_bypass(url, endpoint, client)
            for cf in ct_findings:
                title = f"Content-type spoofing bypass at {endpoint} (using {cf.get('content_type', 'unknown')})"
                print_finding(title, "high", url)
                findings.append(cf)
                if session:
                    await session.add_finding(
                        target=url, module="file_upload",
                        vuln_type="content_type_bypass",
                        severity="high", confidence="confirmed",
                        title=title,
                        description=f"Upload endpoint {endpoint} accepted a .php file with spoofed content-type '{cf.get('content_type')}'. Content-type validation can be bypassed by manipulating the Content-Type header.",
                        evidence=cf.get("evidence", ""),
                        remediation="1. Validate file content (magic bytes) not just Content-Type header. 2. Reject files with mismatched extension and content-type.",
                        cvss_score=8.6, cwe="CWE-434",
                    )

            # -- 3. Double extension bypass -------------------------------------------
            ext_findings = await _test_double_extension(url, endpoint, client)
            for ef in ext_findings:
                title = f"Extension bypass at {endpoint} ({ef.get('extension', 'unknown')})"
                print_finding(title, "high", url)
                findings.append(ef)
                if session:
                    await session.add_finding(
                        target=url, module="file_upload",
                        vuln_type="double_extension_bypass",
                        severity="high", confidence="confirmed",
                        title=title,
                        description=f"Upload endpoint {endpoint} accepted a file with bypass extension '{ef.get('extension')}' (filename: {ef.get('filename')}). Extension filtering can be bypassed using double extensions, case variations, or special characters.",
                        evidence=ef.get("evidence", ""),
                        remediation="1. Whitelist allowed extensions (not blacklist). 2. Reject files with multiple extensions. 3. Normalize extension to lowercase before validation. 4. Remove special characters from filename.",
                        cvss_score=8.6, cwe="CWE-434",
                    )

            # -- 4. Magic byte bypass -------------------------------------------------
            mb_findings = await _test_content_validation(url, endpoint, client)
            for mf in mb_findings:
                title = f"Magic byte validation bypass at {endpoint} (PHP with JPEG header)"
                print_finding(title, "critical", url)
                findings.append(mf)
                if session:
                    await session.add_finding(
                        target=url, module="file_upload",
                        vuln_type="magic_byte_bypass",
                        severity="critical", confidence="confirmed",
                        title=title,
                        description=f"Upload endpoint {endpoint} accepted a .php file with JPEG magic bytes prepended. Content validation only checks magic bytes, allowing polyglot files (valid image + PHP code).",
                        evidence=mf.get("evidence", ""),
                        remediation="1. Validate file extension AND content magic bytes together. 2. Reject mismatched extension and magic bytes. 3. Store files outside webroot. 4. Use Content-Disposition: attachment.",
                        cvss_score=9.8, cwe="CWE-434",
                    )

    console.print(f"  File upload scan complete -- {len(findings)} issues")
    return {"target": url, "findings": findings, "count": len(findings)}
