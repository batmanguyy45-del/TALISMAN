"""Scoped TCP port discovery with bounded concurrency and conservative defaults."""
from __future__ import annotations

import asyncio
from urllib.parse import urlsplit
from typing import Any

from talisman.engine.scope import ScopeViolationError
from talisman.utils.logger import get_logger, console

log = get_logger(__name__)

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888,
    27017, 6379, 5432, 1433, 9200, 9300, 11211, 2181, 5984,
    8086, 7474, 15672, 2379, 2380, 6443, 10250, 10255,
]
MAX_PORTS_PER_RUN = 4096
MAX_CONCURRENCY = 32


async def _tcp_connect(host: str, port: int, timeout: float = 2.0) -> tuple[int, str]:
    writer: asyncio.StreamWriter | None = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        return port, "open"
    except (OSError, asyncio.TimeoutError):
        return port, "closed"
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


def _parse_ports(ports: str) -> list[int]:
    if ports in {"common", "top-100", "top-1000"}:
        # Until curated, audited top-port lists are shipped, these presets
        # intentionally use the conservative common-port set.
        return list(COMMON_PORTS)

    try:
        if "-" in ports:
            start_s, end_s = ports.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                raise ValueError("port range start exceeds end")
            result = list(range(start, end + 1))
        else:
            result = [int(value.strip()) for value in ports.split(",") if value.strip()]
    except (TypeError, ValueError) as exc:
        raise ValueError("Ports must be 'common', a comma-separated list, or a range such as 1-1024") from exc

    if not result or len(result) > MAX_PORTS_PER_RUN:
        raise ValueError(f"Choose between 1 and {MAX_PORTS_PER_RUN} ports per run")
    if any(port < 1 or port > 65535 for port in result):
        raise ValueError("Port numbers must be between 1 and 65535")
    return sorted(set(result))


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    ports: str = "common",
    service_detect: bool = True,
    threads: int = 32,
    **kwargs: Any,
) -> dict[str, Any]:
    if scope is None:
        return {"target": target, "open_ports": [], "count": 0, "error": "scope_enforcer_required"}

    try:
        scope.assert_in_scope(target)
    except ScopeViolationError as exc:
        return {"target": target, "open_ports": [], "count": 0, "error": str(exc)}

    raw_target = target if "://" in target else f"https://{target}"
    parsed = urlsplit(raw_target)
    host = parsed.hostname
    if not host:
        return {"target": target, "open_ports": [], "count": 0, "error": "invalid_target"}

    try:
        port_list = _parse_ports(ports)
    except ValueError as exc:
        return {"target": host, "open_ports": [], "count": 0, "error": str(exc)}

    concurrency = max(1, min(int(threads), MAX_CONCURRENCY))
    console.print(f"\n[module][+] Scoped Port Scanner[/module] -> [target]{host}[/target]")
    console.print(f" Scanning {len(port_list)} ports (max concurrency {concurrency})...")

    sem = asyncio.Semaphore(concurrency)
    open_ports: list[int] = []

    async def scan_one(port: int) -> None:
        async with sem:
            await scope.acquire_request_slot()
            _, status = await _tcp_connect(host, port)
            if status == "open":
                open_ports.append(port)

    await asyncio.gather(*(scan_one(port) for port in port_list))
    open_ports.sort()

    if session and open_ports:
        await session.add_target(
            host,
            notes=f"Open ports: {','.join(str(port) for port in open_ports)}",
        )

    console.print(f" Open ports: {open_ports[:20]}")
    return {"target": host, "open_ports": open_ports, "count": len(open_ports)}
