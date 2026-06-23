"""Port scanner — wraps nmap with Python fallback."""
from __future__ import annotations
import asyncio
import shutil
import socket
from typing import Any
from talisman.utils.logger import get_logger, console

log = get_logger(__name__)

COMMON_PORTS = [
 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888,
 27017, 6379, 5432, 1433, 9200, 9300, 11211, 2181, 5984,
 8086, 7474, 15672, 2379, 2380, 6443, 10250, 10255,
]

async def _tcp_connect(host: str, port: int, timeout: float = 2.0) -> tuple[int, str]:
 try:
  _, writer = await asyncio.wait_for(
   asyncio.open_connection(host, port), timeout=timeout
  )
  writer.close()
  await writer.wait_closed()
  return port, "open"
 except Exception:
  return port, "closed"

async def run(
 target: str,
 session: Any = None,
 scope: Any = None,
 rate_limiter: Any = None,
 proxy: str | None = None,
 ports: str = "common",
 service_detect: bool = True,
 threads: int = 100,
 **kwargs: Any,
) -> dict[str, Any]:
 host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
 console.print(f"\n[module][+] Port Scanner[/module] -> [target]{host}[/target]")

 port_list = COMMON_PORTS
 if ports not in ("common", "top-100", "top-1000"):
  try:
   if "-" in ports:
    start, end = ports.split("-")
    port_list = list(range(int(start), int(end) + 1))
   else:
    port_list = [int(p) for p in ports.split(",")]
  except Exception:
   port_list = COMMON_PORTS

 sem = asyncio.Semaphore(threads)
 open_ports: list[int] = []

 async def _scan(port: int) -> None:
  async with sem:
   _, status = await _tcp_connect(host, port)
   if status == "open":
    open_ports.append(port)

 console.print(f" Scanning {len(port_list)} ports...")
 await asyncio.gather(*[_scan(p) for p in port_list], return_exceptions=True)
 open_ports.sort()
 console.print(f" Open ports: {open_ports[:20]}")

 if session and open_ports:
  await session.add_target(
   host,
   notes=f"Open ports: {','.join(str(p) for p in open_ports)}"
  )

 return {"target": host, "open_ports": open_ports, "count": len(open_ports)}
