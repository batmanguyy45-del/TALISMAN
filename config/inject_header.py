#!/usr/bin/env python3
"""
MITM-style proxy that injects X-HackerOne-Research header into all requests.
Run alongside TALISMAN:  --proxy http://127.0.0.1:8080

Usage:
  python inject_header.py <your_h1_username>

This starts a small forward proxy on 127.0.0.1:8080 that adds:
  X-HackerOne-Research: <your_h1_username>
to every outgoing request.
"""
from __future__ import annotations
import asyncio
import sys


H1_USER = sys.argv[1] if len(sys.argv) > 1 else "YOUR_H1_USERNAME"


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        data = await asyncio.wait_for(reader.read(65536), timeout=30)
        if not data:
            return
        text = data.decode("utf-8", errors="replace")
        # Insert the H1 research header after the first line
        if "\r\n" in text:
            head, rest = text.split("\r\n", 1)
            modified = f"{head}\r\nX-HackerOne-Research: {H1_USER}\r\n{rest}"
        else:
            modified = text
        # Forward to actual destination
        dest_host, dest_port = None, 80
        for line in text.split("\r\n"):
            if line.lower().startswith("host:"):
                host_val = line.split(":", 1)[1].strip()
                if ":" in host_val:
                    dest_host, dest_port_str = host_val.split(":", 1)
                    dest_port = int(dest_port_str)
                else:
                    dest_host = host_val
                    dest_port = 443 if text.upper().startswith("CONNECT") else 80
        if dest_host:
            dest_reader, dest_writer = await asyncio.wait_for(
                asyncio.open_connection(dest_host, dest_port), timeout=10
            )
            dest_writer.write(modified.encode())
            await dest_writer.drain()
            response = await asyncio.wait_for(dest_reader.read(65536), timeout=30)
            writer.write(response)
            await writer.drain()
            dest_writer.close()
    except Exception:
        pass
    finally:
        writer.close()


async def main():
    server = await asyncio.start_server(handle, "127.0.0.1", 8080, reuse_address=True)
    print(f"[+] Header injection proxy running on 127.0.0.1:8080")
    print(f"[+] Injecting X-HackerOne-Research: {H1_USER}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
