"""Database exposure checks with conservative, protocol-backed finding confidence."""
from __future__ import annotations

import asyncio
import socket
from typing import Any

from talisman.utils.logger import console, print_finding

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


async def _tcp_connect(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        conn = asyncio.open_connection(host, port)
        _, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except (OSError, asyncio.TimeoutError, ValueError):
        return False


async def _test_redis(host: str, port: int) -> dict[str, Any] | None:
    """Return data only when Redis answers INFO without authentication."""
    def _sync_probe() -> str:
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=3)
            sock.sendall(b"INFO server\r\n")
            return sock.recv(4096).decode("utf-8", errors="ignore")
        except OSError:
            return ""
        finally:
            if sock is not None:
                sock.close()

    try:
        loop = asyncio.get_running_loop()
        data = await loop.run_in_executor(None, _sync_probe)
    except Exception:
        return None

    if "redis_version:" not in data.lower():
        return None

    version = next(
        (
            line.split(":", 1)[1].strip()
            for line in data.splitlines()
            if line.lower().startswith("redis_version:")
        ),
        "",
    )
    return {
        "db": "Redis",
        "host": host,
        "port": port,
        "version": version,
        "auth_required": False,
        "verified_unauthenticated": True,
        "verification": "Unauthenticated Redis INFO server returned redis_version",
        "sample": data[:200],
    }


async def _test_elasticsearch(host: str, port: int) -> dict[str, Any] | None:
    """Return data only when Elasticsearch exposes cluster metadata unauthenticated."""
    try:
        import httpx

        async with httpx.AsyncClient(verify=True, timeout=5, follow_redirects=False) as client:
            response = await client.get(f"http://{host}:{port}/")
            if response.status_code != 200:
                return None
            data = response.json()
            if not isinstance(data, dict) or not data.get("cluster_name"):
                return None

            indices_response = await client.get(
                f"http://{host}:{port}/_cat/indices?format=json"
            )
            indices: list[str] = []
            if indices_response.status_code == 200:
                try:
                    payload = indices_response.json()
                    if isinstance(payload, list):
                        indices = [
                            item.get("index", "")
                            for item in payload[:10]
                            if isinstance(item, dict)
                        ]
                except ValueError:
                    pass

            return {
                "db": "Elasticsearch",
                "host": host,
                "port": port,
                "cluster_name": data.get("cluster_name"),
                "version": data.get("version", {}).get("number"),
                "indices": indices,
                "auth_required": False,
                "verified_unauthenticated": True,
                "verification": "Unauthenticated HTTP request returned Elasticsearch cluster metadata",
            }
    except Exception:
        return None


async def _test_mongodb(host: str, port: int) -> dict[str, Any] | None:
    """Do not infer missing MongoDB authentication from TCP reachability alone."""
    if await _tcp_connect(host, port, timeout=3.0):
        return {
            "db": "MongoDB",
            "host": host,
            "port": port,
            "service_reachable": True,
            "auth_required": None,
            "verified_unauthenticated": False,
            "note": "TCP port is reachable; MongoDB protocol and authentication were not verified",
        }
    return None


def _is_verified_unauthenticated(result: dict[str, Any] | None) -> bool:
    """A finding requires explicit protocol-level proof, not just an open port."""
    return bool(
        result
        and result.get("auth_required") is False
        and result.get("verified_unauthenticated") is True
    )


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    if scope is not None:
        scope.assert_in_scope(target)

    host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    console.print(f"\n[module][+] Database Exposure Check[/module] -> [target]{host}[/target]")

    exposed: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []

    async def _probe(db: str, port: int) -> None:
        if not await _tcp_connect(host, port):
            return

        console.print(f" [yellow]Reachable port {port} ({db} candidate)[/yellow]")
        result: dict[str, Any] | None = None
        if db == "Redis":
            result = await _test_redis(host, port)
        elif db == "Elasticsearch":
            result = await _test_elasticsearch(host, port)
        elif db == "MongoDB":
            result = await _test_mongodb(host, port)
        else:
            result = {
                "db": db,
                "host": host,
                "port": port,
                "service_reachable": True,
                "verified_unauthenticated": False,
                "auth_required": None,
                "note": "TCP port is reachable; service protocol and authentication were not verified",
            }

        if not _is_verified_unauthenticated(result):
            observations.append(
                result
                or {
                    "db": db,
                    "host": host,
                    "port": port,
                    "service_reachable": True,
                    "verified_unauthenticated": False,
                    "note": "TCP port is reachable, but no protocol-level unauthenticated response was verified",
                }
            )
            console.print(
                f" [dim]Observed {db} candidate on {host}:{port}; "
                "authentication remains unverified[/dim]"
            )
            return

        assert result is not None
        severity = "high"
        title = f"Unauthenticated {db} access on port {port}"
        print_finding(title, severity, f"{host}:{port}")
        exposed.append(result)

        if session:
            reproduction = (
                f"redis-cli -h {host} -p {port} INFO"
                if db == "Redis"
                else f"curl --fail http://{host}:{port}/"
            )
            await session.add_finding(
                target=f"{host}:{port}",
                module="database_exposure",
                vuln_type="unauthenticated_database_access",
                severity=severity,
                confidence="confirmed",
                title=title,
                description=(
                    f"An unauthenticated protocol-level request to {db} at "
                    f"{host}:{port} returned database metadata. The captured "
                    "response demonstrates access without credentials; data "
                    "modification or destructive impact was not tested."
                ),
                evidence=result.get("sample", result.get("verification", str(result)))[:300],
                reproduction=reproduction,
                remediation=(
                    f"1. Restrict {db} to trusted network interfaces only.\n"
                    "2. Require authentication and least-privilege accounts.\n"
                    "3. Apply firewall rules to limit access to authorized systems.\n"
                    "4. Enable TLS where supported."
                ),
                cvss_score=8.6,
                cwe="CWE-306",
            )

    tasks = [
        _probe(db, port)
        for db, ports in DATABASE_PORTS.items()
        for port in ports
    ]
    await asyncio.gather(*tasks, return_exceptions=True)

    console.print(
        f" Confirmed unauthenticated database services: {len(exposed)}; "
        f"unverified reachable services: {len(observations)}"
    )
    return {
        "host": host,
        "exposed": exposed,
        "observations": observations,
        "count": len(exposed),
        "observation_count": len(observations),
    }
