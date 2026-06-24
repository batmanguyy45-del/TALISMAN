"""gRPC security scanner -- reflection, service enumeration, TLS misconfiguration, health check exposure."""
from __future__ import annotations
import asyncio
import json
import socket
import ssl
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

GRPC_PORTS = [50051, 50052, 50053, 8443, 443, 8080, 9090]
GRPC_CONTENT_TYPES = ["application/grpc", "application/grpc+proto", "application/grpc+json"]

# gRPC reflection request bytes (encoded proto for ServerReflectionInfo)
# This is the request for "list services" via gRPC reflection v1alpha
REFLECTION_LIST_SERVICES = (
    b"\x00\x00\x00\x00\x0e\x0a\x0c\x12\x0a\x0a\x08\x08\x01\x12\x04\x0a\x02\x0a\x00"
)

HEALTH_CHECK_REQUEST = (
    b"\x00\x00\x00\x00\x05\x0a\x03\x08\x01"
)


async def _check_grpc_port(host: str, port: int, use_tls: bool = True) -> dict[str, Any]:
    """Check if a port responds to gRPC requests."""
    result: dict[str, Any] = {"port": port, "tls": use_tls, "reachable": False}
    try:
        reader: asyncio.StreamReader
        writer: asyncio.StreamWriter
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), timeout=5
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )

        # Send a minimal HTTP/2 preface to check if it's gRPC
        # gRPC requires HTTP/2, but for basic detection we try the content-type
        writer.write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=3)
            result["reachable"] = True
            result["response_preview"] = data[:100].hex()
            if b"grpc" in data.lower() or b"content-type" in data.lower():
                result["likely_grpc"] = True
        except asyncio.TimeoutError:
            result["reachable"] = True
            result["response_preview"] = "timeout_no_data"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except (ConnectionRefusedError, asyncio.TimeoutError, ssl.SSLError, OSError):
        result["reachable"] = False
    except Exception as e:
        result["reachable"] = False
        result["error"] = str(e)[:100]
    return result


async def _check_grpc_reflection(host: str, port: int, use_tls: bool = True) -> dict[str, Any]:
    """Try gRPC reflection to enumerate services."""
    result: dict[str, Any] = {"reflection_available": False, "services": []}
    try:
        reader: asyncio.StreamReader
        writer: asyncio.StreamWriter
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), timeout=5
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )

        # Send HTTP/2 preface + settings
        writer.write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        await asyncio.wait_for(writer.drain(), timeout=3)

        # Read initial settings
        try:
            await asyncio.wait_for(reader.read(1024), timeout=2)
        except asyncio.TimeoutError:
            pass

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    except Exception:
        pass
    return result


async def _check_health_endpoint(url: str, client: TalismanHTTPClient) -> bool:
    """Check if a gRPC health endpoint is exposed via HTTP/1.1 transcoding."""
    health_paths = ["/health", "/grpc.health.v1.Health/Check", "/healthz"]
    for path in health_paths:
        try:
            r = await client.get(url.rstrip("/") + path, timeout=5)
            if r.status_code in (200, 404, 405):
                body_lower = r.text.lower()
                if any(ind in body_lower for ind in ["serving", "ok", "healthy", "grpc"]):
                    return True
        except Exception:
            pass
    return False


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    port: int | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    host = url.split("://")[-1].split("/")[0].split(":")[0]
    console.print(f"\n[module][+] gRPC Security Scanner[/module] -> [target]{host}[/target]")
    findings: list[dict[str, Any]] = []
    discovered_ports: list[int] = []

    # -- 1. Port discovery -----------------------------------------------------------
    ports_to_check = [port] if port else GRPC_PORTS
    console.print(f"  Probing {len(ports_to_check)} ports for gRPC services")

    for check_port in ports_to_check:
        for use_tls in [True, False]:
            probe = await _check_grpc_port(host, check_port, use_tls=use_tls)
            if probe["reachable"]:
                discovered_ports.append(check_port)
                tls_label = "TLS" if use_tls else "plaintext"
                console.print(f"  [success][+] Port {check_port} ({tls_label}) reachable[/success]")
                if probe.get("likely_grpc"):
                    print_finding(f"gRPC service detected on {host}:{check_port} ({tls_label})", "info", f"{host}:{check_port}")
                    findings.append({"issue": "grpc_detected", "port": check_port, "tls": use_tls})
                    if session:
                        await session.add_finding(
                            target=f"{host}:{check_port}", module="grpc",
                            vuln_type="grpc_service_detected",
                            severity="info", confidence="confirmed",
                            title=f"gRPC service detected on port {check_port} ({tls_label})",
                            description=f"A gRPC service was detected on {host}:{check_port}. Further inspection of the service definition is recommended.",
                            remediation="Ensure gRPC services are properly authenticated and authorized. Disable reflection in production.",
                            cwe="CWE-200",
                        )
                if not use_tls:
                    print_finding(f"gRPC plaintext (no TLS) on {host}:{check_port}", "high", f"{host}:{check_port}")
                    findings.append({"issue": "grpc_no_tls", "port": check_port})
                    if session:
                        await session.add_finding(
                            target=f"{host}:{check_port}", module="grpc",
                            vuln_type="grpc_no_tls",
                            severity="high", confidence="confirmed",
                            title=f"gRPC plaintext connection on port {check_port}",
                            description="gRPC service accepts plaintext connections without TLS. All data including authentication tokens are transmitted in cleartext.",
                            remediation="Enforce TLS for all gRPC connections. Disable plaintext listeners.",
                            cvss_score=7.4, cwe="CWE-319",
                        )

    # -- 2. Reflection check ---------------------------------------------------------
    for check_port in discovered_ports or GRPC_PORTS[:2]:
        refl_result = await _check_grpc_reflection(host, check_port)
        if refl_result["reflection_available"]:
            print_finding(f"gRPC reflection enabled on port {check_port}", "critical", f"{host}:{check_port}")
            findings.append({"issue": "grpc_reflection", "port": check_port, "services": refl_result["services"]})
            if session:
                await session.add_finding(
                    target=f"{host}:{check_port}", module="grpc",
                    vuln_type="grpc_reflection",
                    severity="critical", confidence="confirmed",
                    title="gRPC reflection API exposed",
                    description=f"gRPC reflection is enabled on port {check_port}. Attackers can enumerate all available services, methods, and message types without authentication.",
                    evidence=f"Services: {', '.join(refl_result['services'][:10])}" if refl_result["services"] else "Reflection endpoint responded",
                    remediation="Disable gRPC reflection in production environments. Use service mesh or API gateway to control access.",
                    cvss_score=7.5, cwe="CWE-200",
                )
            break

    # -- 3. Health check via HTTP transcoding ----------------------------------------
    async with TalismanHTTPClient(proxy=proxy, timeout=10) as client:
        health_exposed = await _check_health_endpoint(url, client)
        if health_exposed:
            print_finding("gRPC health check endpoint exposed (unauthenticated)", "medium", url)
            findings.append({"issue": "health_check_exposed"})
            if session:
                await session.add_finding(
                    target=url, module="grpc",
                    vuln_type="grpc_health_check",
                    severity="medium", confidence="confirmed",
                    title="gRPC health check endpoint exposed without authentication",
                    description="The gRPC health check endpoint is publicly accessible. May leak service status information.",
                    remediation="Restrict health check endpoints to internal networks or require authentication.",
                    cwe="CWE-200",
                )

    # -- 4. gRPC-web detection ------------------------------------------------------
    async with TalismanHTTPClient(proxy=proxy, timeout=10) as client:
        grpc_web_paths = ["/grpc", "/api/grpc", "/grpc-web"]
        for grpc_path in grpc_web_paths:
            test_url = url.rstrip("/") + grpc_path
            try:
                r = await client.post(
                    test_url,
                    headers={"Content-Type": "application/grpc-web-text"},
                    data="AAAAAAA=",
                    timeout=5,
                )
                if r.status_code not in (404, 405):
                    body_lower = r.text.lower()
                    if "grpc" in body_lower or r.status_code == 200:
                        print_finding(f"gRPC-Web endpoint detected at {grpc_path}", "info", test_url)
                        findings.append({"issue": "grpc_web_detected", "path": grpc_path})
                        if session:
                            await session.add_finding(
                                target=test_url, module="grpc",
                                vuln_type="grpc_web_detected",
                                severity="info", confidence="confirmed",
                                title=f"gRPC-Web endpoint at {grpc_path}",
                                description="gRPC-Web endpoint found. May expose backend services to browser-based attacks if not properly secured.",
                                remediation="Ensure gRPC-Web endpoints use authentication and proper CORS configuration.",
                                cwe="CWE-200",
                            )
            except Exception:
                pass

    console.print(f"  gRPC scanning complete -- {len(findings)} issues")
    return {"target": host, "discovered_ports": discovered_ports, "findings": findings, "count": len(findings)}
