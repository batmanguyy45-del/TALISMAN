"""SSL/TLS audit — certificate validity, identity and negotiated protocol."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from talisman.engine.scope import ScopeViolationError
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)


def _certificate_matches_host(cert: x509.Certificate, host: str) -> bool:
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
    except x509.ExtensionNotFound:
        return False

    try:
        address = ipaddress.ip_address(host)
        return address in san.get_values_for_type(x509.IPAddress)
    except ValueError:
        names = san.get_values_for_type(x509.DNSName)
        candidate = host.rstrip(".").lower()
        for name in names:
            pattern = name.lower().rstrip(".")
            if pattern.startswith("*."):
                # TLS wildcards cover exactly one left-most label.
                suffix = pattern[2:]
                if candidate.endswith("." + suffix) and candidate.count(".") == suffix.count(".") + 1:
                    return True
            elif candidate == pattern:
                return True
        return False


def _get_cert_info(host: str, connect_ip: str, port: int) -> dict[str, Any]:
    """Retrieve certificate details, including invalid/expired certificates.

    Verification is intentionally disabled only for this inspection handshake:
    otherwise an expired or self-signed certificate could not be examined.
    The target and port are scope-checked before this function is called.
    """
    sock: socket.socket | None = None
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((connect_ip, port), timeout=10)
        with context.wrap_socket(sock, server_hostname=host) as tls_socket:
            raw_cert = tls_socket.getpeercert(binary_form=True)
            return {
                "certificate_der": raw_cert,
                "protocol": tls_socket.version(),
                "cipher": tls_socket.cipher(),
            }
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    if scope is None:
        return {"target": target, "findings": [], "count": 0, "error": "scope_enforcer_required"}
    if proxy:
        return {
            "target": target,
            "findings": [],
            "count": 0,
            "skipped": True,
            "reason": (
                "The raw TLS certificate handshake cannot honor the configured "
                "HTTP proxy; no direct connection was made."
            ),
        }

    url = target if "://" in target else f"https://{target}"
    parsed = urlsplit(url)
    host = parsed.hostname
    if parsed.scheme not in {"http", "https"} or not host:
        return {"target": target, "findings": [], "count": 0, "error": "invalid_target"}

    port = parsed.port or 443
    try:
        async with scope.request_concurrency_slot():
            addresses = await scope.resolve_network_destination(url, "GET")
            await scope.acquire_request_slot()
            connect_ip = str(addresses[0])
            info = await asyncio.to_thread(_get_cert_info, host, connect_ip, port)
    except (ScopeViolationError, ValueError) as exc:
        return {"target": target, "findings": [], "count": 0, "error": str(exc)}

    console.print(f"\n[module][+] SSL/TLS Audit[/module] -> [target]{host}:{port}[/target]")
    if "error" in info:
        console.print(f" [dim]TLS error: {info['error']}[/dim]")
        return {"target": host, "findings": [], "count": 0, "error": info["error"]}

    protocol = info.get("protocol") or ""
    cipher = info.get("cipher") or ()
    raw_cert = info.get("certificate_der")
    findings: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    certificate: x509.Certificate | None = None

    if raw_cert:
        try:
            certificate = x509.load_der_x509_certificate(raw_cert)
        except ValueError as exc:
            return {"target": host, "findings": [], "count": 0, "error": f"certificate_parse_error: {exc}"}

    console.print(f" Protocol: {protocol or 'unknown'}")
    console.print(f" Cipher: {cipher[0] if cipher else 'unknown'}")

    if protocol in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}:
        finding = {"issue": "weak_tls_protocol", "protocol": protocol, "severity": "high"}
        findings.append(finding)
        print_finding(f"Weak TLS protocol: {protocol}", "high", host)
        if session:
            await session.add_finding(
                target=f"https://{host}:{port}", module="ssl_tls",
                vuln_type="weak_tls_protocol", severity="high", confidence="confirmed",
                title=f"Weak TLS protocol in use: {protocol}",
                description=f"The endpoint negotiated {protocol}.",
                evidence=f"Negotiated protocol: {protocol}",
                remediation="Disable SSLv2, SSLv3, TLS 1.0 and TLS 1.1. Require TLS 1.2 or newer.",
                cwe="CWE-326",
            )

    if certificate is not None:
        not_after = getattr(certificate, "not_valid_after_utc", None)
        if not_after is None:
            not_after = certificate.not_valid_after.replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days

        if days_left < 0:
            observations.append({
                "issue": "certificate_expired",
                "days_since_expiry": -days_left,
                "not_after": not_after.isoformat(),
            })
        elif days_left < 30:
            observations.append({
                "issue": "certificate_expiring",
                "days_left": days_left,
                "not_after": not_after.isoformat(),
            })

        if not _certificate_matches_host(certificate, host):
            finding = {"issue": "certificate_hostname_mismatch", "severity": "medium"}
            findings.append(finding)
            print_finding("TLS certificate does not match target hostname", "medium", host)
            if session:
                await session.add_finding(
                    target=f"https://{host}:{port}", module="ssl_tls",
                    vuln_type="certificate_hostname_mismatch", severity="medium",
                    confidence="confirmed",
                    title="TLS certificate hostname does not match target",
                    description="The certificate's Subject Alternative Name extension does not cover the requested host.",
                    evidence=f"Requested host: {host}",
                    remediation="Deploy a certificate whose Subject Alternative Name covers the requested hostname.",
                    cwe="CWE-295",
                )

    console.print(f" TLS audit complete — {len(findings)} issues")
    return {
        "target": host,
        "port": port,
        "resolved_ip": connect_ip,
        "protocol": protocol,
        "cipher": cipher[0] if cipher else None,
        "findings": findings,
        "observations": observations,
        "count": len(findings),
    }
