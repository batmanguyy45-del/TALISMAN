"""Scoped database service discovery with evidence-led unauthenticated checks."""
from __future__ import annotations

import asyncio
import socket
from typing import Any
from urllib.parse import urlsplit

from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

DATABASE_PORTS = {
    "MongoDB": [27017, 27018, 27019],
    "Redis": [6379, 6380],
    "Elasticsearch": [9200, 9300],
    "Memcached": [11211],
    "CouchDB": [5984, 6984],
    "InfluxDB": [8086],
    "Cassandra": [9042, 9160],
    "Neo4j": [7474, 7473],
    "RabbitMQ": [15672, 5672],
    "MySQL": [3306, 33060],
    "PostgreSQL": [5432],
    "MSSQL": [1433, 1434],
}


async def _tcp_connect(host: str, port: int, scope: Any, timeout: float = 3.0) -> bool:
    request_url = f"http://{host}:{port}/"
    async with scope.request_concurrency_slot():
        addresses = await scope.resolve_network_destination(request_url, "GET")
        await scope.acquire_request_slot()
        writer: asyncio.StreamWriter | None = None
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(str(addresses[0]), port),
                timeout=timeout,
            )
            return True
        except (OSError, TimeoutError):
            return False
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass


async def _test_redis(host: str, port: int, scope: Any) -> dict[str, Any] | None:
    """Check whether Redis permits a harmless INFO command without credentials."""
    request_url = f"http://{host}:{port}/"
    async with scope.request_concurrency_slot():
        addresses = await scope.resolve_network_destination(request_url, "GET")
        await scope.acquire_request_slot()

        def probe() -> str:
            with socket.create_connection((str(addresses[0]), port), timeout=3) as sock:
                sock.settimeout(3)
                sock.sendall(b"INFO server\\r\\n")
                data = sock.recv(4096)
                return data.decode("utf-8", errors="replace")

        try:
            data = await asyncio.to_thread(probe)
        except OSError:
            return None

    if "redis_version" not in data.lower():
        return None
    version = next(
        (line.split(":", 1)[1].strip() for line in data.splitlines()
         if line.lower().startswith("redis_version:")),
        "",
    )
    return {
        "db": "Redis",
        "host": host,
        "port": port,
        "version": version,
        "unauthenticated_info": True,
        "sample": data[:200],
    }


async def _test_elasticsearch(host: str, port: int, scope: Any) -> dict[str, Any] | None:
    """Read only root cluster metadata; never enumerate indices or documents."""
    url = f"http://{host}:{port}/"
    try:
        async with TalismanHTTPClient(scope=scope, timeout=5) as client:
            response = await client.get(url)
        if response.status_code != 200:
            return None
        data = response.json()
        if not isinstance(data, dict) or not data.get("cluster_name"):
            return None
        return {
            "db": "Elasticsearch",
            "host": host,
            "port": port,
            "cluster_name": str(data.get("cluster_name", ""))[:100],
            "version": data.get("version", {}).get("number") if isinstance(data.get("version"), dict) else None,
            "unauthenticated_metadata": True,
        }
    except (ValueError, OSError):
        return None
    except Exception:
        return None


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    if scope is None:
        return {"target": target, "services": [], "findings": [], "count": 0, "error": "scope_enforcer_required"}
    if proxy:
        return {
            "target": target,
            "services": [],
            "findings": [],
            "count": 0,
            "skipped": True,
            "reason": (
                "Database protocol probes use raw TCP and cannot honor the "
                "configured HTTP proxy; no direct connections were made."
            ),
        }

    parsed = urlsplit(target if "://" in target else f"https://{target}")
    host = parsed.hostname
    if parsed.scheme not in {"http", "https"} or not host:
        return {"target": target, "services": [], "findings": [], "count": 0, "error": "invalid_target"}
    try:
        scope.assert_in_scope(target)
    except ScopeViolationError as exc:
        return {"target": target, "services": [], "findings": [], "count": 0, "error": str(exc)}

    console.print(f"\n[module][+] Database Service Exposure Check[/module] -> [target]{host}[/target]")
    services: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    sem = asyncio.Semaphore(8)

    async def probe_service(database: str, port: int) -> None:
        async with sem:
            try:
                is_open = await _tcp_connect(host, port, scope)
            except ScopeViolationError:
                return
            if not is_open:
                return

            service = {"db": database, "host": host, "port": port, "verified_exposure": False}
            evidence: dict[str, Any] | None = None
            if database == "Redis":
                evidence = await _test_redis(host, port, scope)
            elif database == "Elasticsearch":
                evidence = await _test_elasticsearch(host, port, scope)

            if evidence:
                service.update(evidence)
                service["verified_exposure"] = True
                findings.append(service)
                severity = "medium" if database == "Redis" else "low"
                title = (
                    f"Unauthenticated Redis INFO access on {host}:{port}"
                    if database == "Redis"
                    else f"Unauthenticated Elasticsearch cluster metadata on {host}:{port}"
                )
                print_finding(title, severity, f"{host}:{port}")
                if session:
                    await session.add_finding(
                        target=f"{host}:{port}",
                        module="database_exposure",
                        vuln_type=f"unauthenticated_{database.lower()}_metadata",
                        severity=severity,
                        confidence="confirmed",
                        title=title,
                        description=(
                            "A read-only unauthenticated metadata request succeeded. "
                            "This proves the metadata operation is accessible without credentials; "
                            "it does not by itself prove that data can be read or modified."
                        ),
                        evidence=str(evidence.get("sample") or evidence)[:300],
                        reproduction=(
                            f"Connect to {host}:{port} and issue the Redis INFO command."
                            if database == "Redis"
                            else f"Send GET / to http://{host}:{port}/ and inspect the cluster metadata response."
                        ),
                        remediation="Restrict the database listener to trusted networks and require authentication for management access.",
                        cwe="CWE-306",
                    )
            else:
                service["note"] = "TCP port is open; protocol authentication and data access were not verified."
                services.append(service)
                console.print(f" [dim]Open {database} port {port}; authentication not verified[/dim]")

    jobs = [
        probe_service(database, port)
        for database, ports in DATABASE_PORTS.items()
        for port in ports
    ]
    await asyncio.gather(*jobs, return_exceptions=True)

    console.print(f" Database check complete — {len(findings)} verified metadata exposures, {len(services)} unverified open ports")
    return {
        "host": host,
        "services": services,
        "findings": findings,
        "count": len(findings),
        "open_ports_unverified": len(services),
    }
