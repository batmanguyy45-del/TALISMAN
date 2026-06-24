"""Scope enforcement — every outbound request passes through here."""
from __future__ import annotations
import ipaddress
import re
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Union
from urllib.parse import urlparse
import yaml
from talisman.utils.logger import get_logger

log = get_logger(__name__)

@dataclass
class ScopeConfig:
 include: list[str] = field(default_factory=list)
 exclude: list[str] = field(default_factory=list)
 max_requests_per_second: float = 50.0
 avoid_writes: bool = False
 avoid_destructive: bool = True
 respect_robots_txt: bool = False

 @classmethod
 def from_file(cls, path: Path) -> "ScopeConfig":
  with open(path) as f:
   data = yaml.safe_load(f)
  restrictions = data.get("restrictions", {})
  return cls(
   include=data.get("include", []),
   exclude=data.get("exclude", []),
   max_requests_per_second=restrictions.get("max_requests_per_second", 50.0),
   avoid_writes=restrictions.get("avoid_writes", False),
   avoid_destructive=restrictions.get("avoid_destructive", True),
   respect_robots_txt=restrictions.get("respect_robots_txt", False),
  )

 @classmethod
 def from_target(cls, target: str) -> "ScopeConfig":
  """Create permissive scope from a single target string."""
  parsed = urlparse(target if "://" in target else f"https://{target}")
  domain = parsed.netloc or parsed.path
  base = domain.split(":")[0]
  return cls(include=[base, f"*.{base}"])


class ScopeEnforcer:
 def __init__(self, config: ScopeConfig):
  self.config = config
  self._include_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
  self._exclude_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
  for entry in config.include:
   try:
    self._include_nets.append(ipaddress.ip_network(entry, strict=False))
   except ValueError:
    pass
  for entry in config.exclude:
   try:
    self._exclude_nets.append(ipaddress.ip_network(entry, strict=False))
   except ValueError:
    pass

 def _extract_host(self, target: str) -> str:
  if "://" in target:
   parsed = urlparse(target)
   return (parsed.hostname or "").lower()
  return target.split(":")[0].lower().strip("/")

 def _match_pattern(self, host: str, pattern: str) -> bool:
  pattern = pattern.lower().strip()
  if pattern.startswith("*."):
   suffix = pattern[2:]
   return host.endswith("." + suffix)
  if "/" in pattern:
   return False
  return fnmatch(host, pattern) or host == pattern

 def _match_cidr(self, host: str, nets: list) -> bool:
  try:
   addr = ipaddress.ip_address(host)
   return any(addr in net for net in nets)
  except ValueError:
   return False

 def _match_url_pattern(self, url: str, pattern: str) -> bool:
  if "*" in pattern or "?" in pattern:
   regex = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
   return bool(re.match(regex, url, re.IGNORECASE))
  return url.lower().startswith(pattern.lower())

 def is_in_scope(self, target: str) -> bool:
  host = self._extract_host(target)
  url = target if "://" in target else f"https://{target}"
  in_scope = False
  for pattern in self.config.include:
   if self._match_pattern(host, pattern):
    in_scope = True
    break
   if self._match_cidr(host, self._include_nets):
    in_scope = True
    break
   if "/" in pattern or "?" in pattern:
    if self._match_url_pattern(url, pattern):
     in_scope = True
     break
  if not in_scope:
   log.debug("out_of_scope", target=target)
   return False
  for pattern in self.config.exclude:
   if self._match_pattern(host, pattern):
    log.debug("excluded_scope", target=target, pattern=pattern)
    return False
   if self._match_cidr(host, self._exclude_nets):
    log.debug("excluded_cidr", target=target)
    return False
   if "/" in pattern or "?" in pattern:
    if self._match_url_pattern(url, pattern):
     log.debug("excluded_url", target=target, pattern=pattern)
     return False
  return True

 def filter_targets(self, targets: list[str]) -> list[str]:
  return [t for t in targets if self.is_in_scope(t)]

 def assert_in_scope(self, target: str) -> None:
  if not self.is_in_scope(target):
   raise ScopeViolationError(f"Target '{target}' is out of scope")


class ScopeViolationError(Exception):
 """Raised when a target is out of scope."""
