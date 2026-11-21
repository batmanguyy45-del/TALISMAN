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
    if scope is None:
        return {
            "target": url,
            "findings": [],
            "candidates": [],
            "count": 0,
            "error": "scope_enforcer_required",
        }
    try:
        scope.assert_destructive_allowed(url, "POST")
    except Exception as exc:
        return {
            "target": url,
            "findings": [],
            "candidates": [],
            "count": 0,
            "skipped": True,
            "reason": str(exc),
        }

    console.print(
        f"\n[module][+] File Upload Candidate Scanner[/module] -> [target]{url}[/target]"
    )
    candidates: list[dict[str, Any]] = []

    async with TalismanHTTPClient(
        proxy=proxy,
        timeout=15,
        scope=scope,
    ) as client:
        for endpoint in UPLOAD_ENDPOINTS:
            probes = (
                ("script_upload_acceptance", await _test_upload_endpoint(url, endpoint, client)),
                ("content_type_spoofing", await _test_content_type_bypass(url, endpoint, client)),
                ("double_extension", await _test_double_extension(url, endpoint, client)),
                ("magic_byte", await _test_content_validation(url, endpoint, client)),
            )
            for probe_type, results in probes:
                for result in results:
                    candidate = {
                        **result,
                        "endpoint": endpoint,
                        "probe_type": probe_type,
                        "confidence": "candidate",
                        "requires_follow_up": True,
                        "verification_required": (
                            "Confirm the uploaded object was persisted, identify its "
                            "server-side storage URL, verify access controls, and safely "
                            "determine whether the server executes or serves the content "
                            "with an unsafe type. HTTP 200/201 or a reflected canary alone "
                            "does not prove executable or publicly accessible upload."
                        ),
                    }
                    candidates.append(candidate)

    console.print(
        f"  Found {len(candidates)} upload candidates requiring storage and execution verification"
    )
    return {
        "target": url,
        "findings": [],
        "candidates": candidates,
        "count": 0,
        "candidate_count": len(candidates),
    }
