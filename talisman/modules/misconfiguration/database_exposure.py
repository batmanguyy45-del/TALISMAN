"""Database exposure detection — MongoDB, Redis, Elasticsearch, Memcached."""
from __future__ import annotations
import asyncio
import json
import socket
from typing import Any
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

DATABASE_PORTS = {
    "MongoDB":       [27017, 27018, 27019],
    "Redis":         [6379, 6380],
    "Elasticsearch": [9200, 9300],
    "Memcached":     [11211],
    "CouchDB":       [5984, 6984],
    "InfluxDB":      [8086],
    "Cassandra":     [9042, 9160],
    "Neo4j":         [7474, 7473],
    "RabbitMQ":      [15672, 5672],
    "MySQL":         [3306, 33060],
    "PostgreSQL":    [5432],
    "MSSQL":         [1433, 1434],
}

async def _tcp_connect(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        loop = asyncio.get_event_loop()
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

async def _test_redis(host: str, port: int) -> dict[str, Any] | None:
    try:
        loop = asyncio.get_event_loop()
        def _sync():
            try:
                s = socket.create_connection((host, port), timeout=3)
                s.sendall(b"INFO server\r\n")
                data = s.recv(4096).decode("utf-8", errors="ignore")
                s.close()
                return data
            except Exception:
                return ""
        data = await loop.run_in_executor(None, _sync)
        if "redis_version" in data.lower() or "+OK" in data:
            version = ""
            for line in data.splitlines():
                if "redis_version:" in line.lower():
                    version = line.split(":")[-1].strip()
            return {"db": "Redis", "host": host, "port": port,
                    "version": version, "auth_required": False,
                    "sample": data[:200]}
    except Exception:
        pass
    return None

async def _test_elasticsearch(host: str, port: int) -> dict[str, Any] | None:
    try:
        import httpx
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            r = await client.get(f"http://{host}:{port}/")
            if r.status_code == 200 and "cluster_name" in r.text:
                data = r.json()
                indices_r = await client.get(f"http://{host}:{port}/_cat/indices?format=json")
                indices = []
                if indices_r.status_code == 200:
                    indices = [i.get("index", "") for i in indices_r.json()[:10]]
                return {
                    "db": "Elasticsearch",
                    "host": host, "port": port,
                    "cluster_name": data.get("cluster_name"),
                    "version": data.get("version", {}).get("number"),
                    "indices": indices,
                    "auth_required": False,
                }
    except Exception:
        pass
    return None

async def _test_mongodb(host: str, port: int) -> dict[str, Any] | None:
    if await _tcp_connect(host, port, timeout=3.0):
        # Can't easily test without pymongo, but flag it as open
        return {"db": "MongoDB", "host": host, "port": port,
                "note": "Port open — manual authentication check required"}
    return None

async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    console.print(f"\n[module]⚡ Database Exposure Check[/module] → [target]{host}[/target]")
    exposed: list[dict[str, Any]] = []

    checks: list[asyncio.Task] = []
    async def _probe(db: str, port: int) -> None:
        open_port = await _tcp_connect(host, port)
        if not open_port:
            return
        console.print(f"  [yellow]Open port {port} ({db})[/yellow]")
        result: dict[str, Any] | None = None
        if db == "Redis":
            result = await _test_redis(host, port)
        elif db == "Elasticsearch":
            result = await _test_elasticsearch(host, port)
        elif db == "MongoDB":
            result = await _test_mongodb(host, port)
        else:
            result = {"db": db, "host": host, "port": port, "note": "Port open — verify manually"}
        if result:
            severity = "critical" if result.get("auth_required") is False else "high"
            title = f"Exposed {db} on port {port}" + (" (no auth)" if not result.get("auth_required", True) else "")
            print_finding(title, severity, f"{host}:{port}")
            exposed.append(result)
            if session:
                await session.add_finding(
                    target=f"{host}:{port}", module="database_exposure",
                    vuln_type="exposed_database",
                    severity=severity, confidence="confirmed",
                    title=title,
                    description=(
                        f"{db} database exposed on {host}:{port} without authentication. "
                        f"An attacker can read, modify, or delete all data."
                    ),
                    evidence=result.get("sample", str(result))[:300],
                    reproduction=f"Connect: redis-cli -h {host} -p {port}" if db == "Redis"
                                 else f"curl http://{host}:{port}/",
                    remediation=(
                        f"1. Bind {db} to localhost or internal network interfaces only.\n"
                        "2. Enable authentication.\n"
                        "3. Use firewall rules to restrict access to authorized IPs.\n"
                        "4. Encrypt traffic with TLS."
                    ),
                    cvss_score=10.0 if not result.get("auth_required", True) else 8.6,
                    cwe="CWE-306",
                )

    tasks = []
    for db, ports in DATABASE_PORTS.items():
        for port in ports:
            tasks.append(_probe(db, port))
    await asyncio.gather(*tasks, return_exceptions=True)

    console.print(f"  Found {len(exposed)} exposed databases")
    return {"host": host, "exposed": exposed, "count": len(exposed)}
