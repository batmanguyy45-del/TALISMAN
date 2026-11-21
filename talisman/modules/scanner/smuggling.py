"""HTTP Request Smuggling — CL.TE, TE.CL, TE.TE obfuscation, H2 downgrade, response-based confirmation."""
from __future__ import annotations
import asyncio
import socket
import ssl
import time
from typing import Any
from urllib.parse import urlsplit
from talisman.engine.scope import ScopeViolationError
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


async def _raw_send(
    host: str,
    port: int,
    use_tls: bool,
    data: bytes,
    scope: Any,
    request_url: str,
    timeout: int = 10,
) -> bytes:
    """Send one raw probe only after scope, write-policy and rate checks."""
    scope.assert_destructive_allowed(request_url, "POST")
    addresses = await scope.resolve_network_destination(request_url, "POST")
    connect_ip = str(addresses[0])
    await scope.acquire_request_slot()

    def _sync_send() -> bytes:
        sock: socket.socket | None = None
        try:
            sock = socket.create_connection((connect_ip, port), timeout=timeout)
            if use_tls:
                # Keep normal CA and hostname verification enabled.
                ctx = ssl.create_default_context()
                wrapped = ctx.wrap_socket(sock, server_hostname=host)
                sock = wrapped
            sock.settimeout(timeout)
            sock.sendall(data)
            response = bytearray()
            while len(response) < 65536:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                response.extend(chunk)
            return bytes(response)
        except Exception as exc:
            return f"ERROR: {type(exc).__name__}: {exc}".encode()
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    return await asyncio.to_thread(_sync_send)


async def _detect_timing_differential(
    host: str, port: int, use_tls: bool, probe: bytes, scope: Any, request_url: str
) -> tuple[bool, float, bytes]:
    start = time.monotonic()
    response = await _raw_send(host, port, use_tls, probe, scope, request_url, timeout=8)
    elapsed = time.monotonic() - start
    return elapsed > 5.0, elapsed, response



def _http_response_bodies(raw: bytes, max_responses: int = 4) -> list[bytes]:
    """Extract bodies only when HTTP/1 framing makes response boundaries unambiguous."""
    bodies: list[bytes] = []
    offset = 0

    while offset < len(raw) and len(bodies) < max_responses:
        header_end = raw.find(b"\r\n\r\n", offset)
        if header_end < 0:
            break

        header_block = raw[offset:header_end]
        lines = header_block.split(b"\r\n")
        if not lines or not lines[0].startswith(b"HTTP/"):
            break

        headers: dict[bytes, bytes] = {}
        for line in lines[1:]:
            name, separator, value = line.partition(b":")
            if separator:
                headers[name.strip().lower()] = value.strip().lower()

        body_start = header_end + 4
        status_parts = lines[0].split()
        try:
            status_code = int(status_parts[1])
        except (IndexError, ValueError):
            break

        if 100 <= status_code < 200 or status_code in {204, 304}:
            bodies.append(b"")
            offset = body_start
            continue

        transfer_encoding = headers.get(b"transfer-encoding", b"")
        if b"chunked" in transfer_encoding:
            cursor = body_start
            decoded = bytearray()
            complete = False
            while cursor < len(raw):
                line_end = raw.find(b"\r\n", cursor)
                if line_end < 0:
                    break
                size_text = raw[cursor:line_end].split(b";", 1)[0].strip()
                try:
                    chunk_size = int(size_text, 16)
                except ValueError:
                    break
                cursor = line_end + 2
                if chunk_size == 0:
                    trailer_end = raw.find(b"\r\n\r\n", cursor)
                    if raw[cursor:cursor + 2] == b"\r\n":
                        cursor += 2
                    elif trailer_end >= 0:
                        cursor = trailer_end + 4
                    else:
                        break
                    complete = True
                    break
                chunk_end = cursor + chunk_size
                if chunk_end + 2 > len(raw) or raw[chunk_end:chunk_end + 2] != b"\r\n":
                    break
                decoded.extend(raw[cursor:chunk_end])
                cursor = chunk_end + 2
            if not complete:
                break
            bodies.append(bytes(decoded))
            offset = cursor
            continue

        content_length = headers.get(b"content-length")
        if content_length is None:
            # Close-delimited responses cannot safely be split from a possible
            # second response on the same connection.
            break
        try:
            length = int(content_length)
        except ValueError:
            break
        if length < 0 or body_start + length > len(raw):
            break
        bodies.append(raw[body_start:body_start + length])
        offset = body_start + length

    return bodies


async def _confirm_smuggling(
    host: str, port: int, use_tls: bool, technique: str, probe: bytes,
    scope: Any, request_url: str, host_header: str
) -> dict[str, Any]:
    """Send probe twice — if the prefix appears in the *second* response, smuggling confirmed."""
    result: dict[str, Any] = {"confirmed": False, "evidence": "", "timing_differential": False}

    # First: timing-based detection
    timing_hit, elapsed, first_resp = await _detect_timing_differential(host, port, use_tls, probe, scope, request_url)
    result["timing_differential"] = timing_hit
    result["first_response"] = first_resp[:200].decode("utf-8", errors="replace")

    if timing_hit and b"ERROR" not in first_resp:
        # Second: send two requests back-to-back — the smuggled prefix should pollute the second
        normal_get = (
            f"GET / HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n"
        ).encode()
        combined = probe + normal_get
        combined_resp = await _raw_send(host, port, use_tls, combined, scope, request_url, timeout=8)
        resp_text = combined_resp.decode("utf-8", errors="replace")
        result["combined_response"] = resp_text[:500]

        response_bodies = _http_response_bodies(combined_resp)
        result["response_count"] = len(response_bodies)
        if len(response_bodies) >= 2 and SMUGGLING_PREFIX.encode().lower() in response_bodies[1].lower():
            result["confirmed"] = True
            result["evidence"] = (
                f"Smuggled prefix '{SMUGGLING_PREFIX}' found in the second "
                "framed HTTP response body"
            )
        elif timing_hit:
            result["evidence"] = (
                f"Timing differential ({elapsed:.1f}s) suggests {technique} desync; "
                "the second response did not contain the marker"
            )

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
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return {
            "target": target,
            "findings": [],
            "candidates": [],
            "count": 0,
            "error": "invalid_http_target",
        }
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
    except ScopeViolationError as exc:
        return {
            "target": url,
            "findings": [],
            "candidates": [],
            "count": 0,
            "skipped": True,
            "reason": str(exc),
        }

    # This module uses raw TCP/TLS sockets to preserve malformed HTTP framing.
    # It cannot safely tunnel these probes through a generic HTTP proxy. Never
    # silently bypass the operator's configured proxy.
    if proxy:
        return {
            "target": url,
            "findings": [],
            "candidates": [],
            "count": 0,
            "skipped": True,
            "reason": (
                "Raw request-smuggling probes cannot honor the configured proxy; "
                "the scan was stopped rather than sending traffic directly."
            ),
        }

    use_tls = parsed.scheme == "https"
    host = parsed.hostname
    port = parsed.port or (443 if use_tls else 80)
    host_header = parsed.netloc
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    console.print(
        f"\\n[module][+] HTTP Request Smuggling Assessment[/module] -> [target]{url}[/target]"
    )
    findings: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []

    probes = [
        ("CL.TE", _build_cl_te_probe(host_header, path)),
        ("TE.CL", _build_te_cl_probe(host_header, path)),
        *[
            (f"TE.TE ({name})", probe)
            for name, probe in _build_te_te_variants(host_header, path)
        ],
        ("H2 downgrade", _build_h2_downgrade_probe(host_header, path)),
    ]

    for technique, probe in probes:
        console.print(f"  Testing {technique}...")
        result = await _confirm_smuggling(
            host,
            port,
            use_tls,
            technique,
            probe,
            scope,
            url,
            host_header,
        )
        if not isinstance(result, dict):
            continue

        record = {"technique": technique, **result}
        if result.get("confirmed") is True:
            severity = "high"
            title = f"HTTP Request Smuggling — {technique} (parser-boundary evidence)"
            record.update({
                "confidence": "confirmed",
                "requires_impact_validation": True,
                "severity": severity,
            })
            findings.append(record)
            print_finding(title, severity, url)
            if session:
                await session.add_finding(
                    target=url,
                    module="smuggling",
                    vuln_type=f"http_smuggling_{technique.lower().replace(' ', '_').replace('.', '_').replace('(', '').replace(')', '')}",
                    severity=severity,
                    confidence="confirmed",
                    title=title,
                    description=(
                        f"The {technique} probe caused the unique smuggled marker "
                        "to appear in a separately framed subsequent HTTP response. "
                        "This confirms a request-parser boundary discrepancy; the "
                        "impact on other users or application data still requires "
                        "separate validation."
                    ),
                    evidence=str(result.get("evidence", ""))[:2000],
                    reproduction=(
                        f"Send the recorded {technique} probe to {url} and verify "
                        "the unique marker appears in the separately framed "
                        "subsequent response."
                    ),
                    remediation=(
                        "Reject ambiguous or conflicting message-framing headers, "
                        "normalize request framing at the edge, and use a consistent "
                        "HTTP parser across proxy and application tiers."
                    ),
                    cwe="CWE-444",
                    extra={"requires_impact_validation": True},
                )
        elif result.get("timing_differential") is True:
            candidate = {
                **record,
                "confidence": "candidate",
                "requires_manual_verification": True,
                "verification_required": (
                    "Repeat against a stable baseline and rule out latency, rate "
                    "limiting, connection reuse, server load, and timeout noise. "
                    "A timing oracle alone does not establish request smuggling."
                ),
            }
            candidates.append(candidate)
            console.print(
                f"  [dim]Timing-only candidate for {technique}; not promoted to finding[/dim]"
            )

    console.print(
        f"  Smuggling assessment complete — {len(findings)} confirmed parser-boundary "
        f"findings, {len(candidates)} timing candidates"
    )
    return {
        "target": url,
        "findings": findings,
        "candidates": candidates,
        "count": len(findings),
        "candidate_count": len(candidates),
    }
