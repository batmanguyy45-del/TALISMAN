"""Scoped gRPC service discovery, TLS transport checks and health endpoint review."""
from __future__ import annotations
import asyncio
import ssl
from typing import Any
from urllib.parse import urlsplit
from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

GRPC_PORTS = [50051, 50052, 50053, 8443, 443, 8080, 9090]
# gRPC reflection request bytes (encoded proto for ServerReflectionInfo)
# This is the request for "list services" via gRPC reflection v1alpha
REFLECTION_LIST_SERVICES = (
    b"\x00\x00\x00\x00\x0e\x0a\x0c\x12\x0a\x0a\x08\x08\x01\x12\x04\x0a\x02\x0a\x00"
)

HEALTH_CHECK_REQUEST = (
    b"\x00\x00\x00\x00\x05\x0a\x03\x08\x01"
)


async def _check_grpc_port(
    host: str, port: int, use_tls: bool, scope: Any, request_url: str
) -> dict[str, Any]:
    """Check if a scoped port speaks the HTTP/2 preface used by gRPC."""
    async with scope.request_concurrency_slot():
        addresses = await scope.resolve_network_destination(request_url, "GET")
        await scope.acquire_request_slot()
        connect_ip = str(addresses[0])
        result: dict[str, Any] = {
            "port": port,
            "tls": use_tls,
            "reachable": False,
            "resolved_ip": connect_ip,
        }
        try:
            reader: asyncio.StreamReader
            writer: asyncio.StreamWriter
            if use_tls:
                ctx = ssl.create_default_context()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        connect_ip,
                        port,
                        ssl=ctx,
                        server_hostname=host,
                    ),
                    timeout=5,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(connect_ip, port), timeout=5
                )

            # Send a minimal HTTP/2 preface to check if it's gRPC
            # gRPC requires HTTP/2, but for basic detection we try the content-type
            writer.write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            await writer.drain()
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


async def _check_health_endpoint(url: str, client: TalismanHTTPClient) -> bool:
    """Check if a gRPC health endpoint is exposed via HTTP/1.1 transcoding."""
    health_paths = ["/health", "/grpc.health.v1.Health/Check", "/healthz"]
    for path in health_paths:
        try:
            r = await client.get(url.rstrip("/") + path, timeout=5)
            if r.status_code == 200:
                body_lower = r.text.lower()
                if any(ind in body_lower for ind in ["serving", "not_serving", "grpc.health.v1.health"]):
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
    parsed = urlsplit(url)
    host = parsed.hostname
    if parsed.scheme not in {"http", "https"} or not host:
        return {"target": target, "discovered_ports": [], "findings": [], "count": 0, "error": "invalid_target"}
    if scope is None:
        return {"target": host, "discovered_ports": [], "findings": [], "count": 0, "error": "scope_enforcer_required"}
    try:
        scope.assert_in_scope(url)
    except ScopeViolationError as exc:
        return {"target": host, "discovered_ports": [], "findings": [], "count": 0, "error": str(exc)}
    console.print(f"\n[module][+] gRPC Security Scanner[/module] -> [target]{host}[/target]")
    findings: list[dict[str, Any]] = []
    discovered_ports: list[int] = []

    # -- 1. Port discovery -----------------------------------------------------------
    ports_to_check = [] if proxy else ([port] if port else GRPC_PORTS)
    if proxy:
        console.print(
            "  [dim]Raw gRPC port probes skipped because they cannot honor the HTTP proxy[/dim]"
        )
    else:
        console.print(f"  Probing {len(ports_to_check)} ports for gRPC services")

    for check_port in ports_to_check:
        for use_tls in [True, False]:
            probe_url = f"{'https' if use_tls else 'http'}://{host}:{check_port}/"
            try:
                probe = await _check_grpc_port(host, check_port, use_tls, scope, probe_url)
            except ScopeViolationError:
                continue
            if probe["reachable"] and probe.get("likely_grpc"):
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
                                )
                if not use_tls and probe.get("likely_grpc"):
                    print_finding(
                        f"gRPC plaintext transport observed on {host}:{check_port}",
                        "info",
                        f"{host}:{check_port}",
                    )
                    findings.append(
                        {
                            "issue": "grpc_plaintext_transport",
                            "port": check_port,
                            "severity": "info",
                            "resolved_ip": probe.get("resolved_ip"),
                        }
                    )
                    if session:
                        await session.add_finding(
                            target=f"{host}:{check_port}",
                            module="grpc",
                            vuln_type="grpc_plaintext_transport",
                            severity="info",
                            confidence="confirmed",
                            title=f"Plaintext gRPC transport observed on port {check_port}",
                            description=(
                                "The endpoint accepted an HTTP/2 gRPC preface without TLS. "
                                "This is a transport-security observation only; it does not "
                                "prove that authentication material or sensitive data is sent "
                                "over this listener."
                            ),
                            evidence=f"Plaintext HTTP/2 preface accepted on {host}:{check_port}",
                            remediation=(
                                "Use TLS where confidentiality or integrity is required, "
                                "and verify that clients do not send sensitive data over "
                                "plaintext listeners."
                            ),
                            cwe="CWE-319",
                        )

    # -- 3. Health check via HTTP transcoding ----------------------------------------
    async with TalismanHTTPClient(proxy=proxy, timeout=10, scope=scope) as client:
        health_exposed = await _check_health_endpoint(url, client)
        if health_exposed:
            print_finding("gRPC health endpoint responds publicly (informational)", "info", url)
            findings.append({"issue": "health_check_exposed"})
            if session:
                await session.add_finding(
                    target=url, module="grpc",
                    vuln_type="grpc_health_endpoint_public",
                    severity="info", confidence="likely",
                    title="Public gRPC health endpoint responds",
                    description="A health endpoint returned a gRPC-specific service status. This is informational and does not establish an authorization vulnerability by itself.",
                    remediation="Restrict health check endpoints to internal networks or require authentication.",
                    cwe="CWE-200",
                )

    # -- 4. gRPC-web detection ------------------------------------------------------
    # This probe sends POST to guessed RPC paths. It is not part of a
    # read-only assessment and must pass the separate destructive-probe gate.
    try:
        scope.assert_destructive_allowed(url, "POST")
    except ScopeViolationError:
        console.print("  [dim]gRPC-Web POST probes skipped: destructive testing is disabled[/dim]")
    else:
        async with TalismanHTTPClient(proxy=proxy, timeout=10, scope=scope) as client:
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
                                    severity="info", confidence="candidate",
                                    title=f"gRPC-Web endpoint at {grpc_path}",
                                    description=(
                                        "A response was received from a guessed gRPC-Web path. "
                                        "This indicates a possible gRPC-Web endpoint; verify the "
                                        "service protocol and authorization before reporting."
                                    ),
                                    remediation="Ensure gRPC-Web endpoints use authentication and proper CORS configuration.",
                                    cwe="CWE-200",
                                )
                except Exception:
                    pass

    console.print(f"  gRPC scanning complete -- {len(findings)} issues")
    return {
        "target": host,
        "discovered_ports": discovered_ports,
        "raw_port_probes_skipped": bool(proxy),
        "findings": findings,
        "count": len(findings),
    }
