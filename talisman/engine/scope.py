"""Scope enforcement shared by the CLI and every TALISMAN HTTP request."""
from __future__ import annotations

import ipaddress
import re
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Iterator
from urllib.parse import urlsplit

import yaml
from talisman.utils.logger import get_logger

log = get_logger(__name__)

_ACTIVE_SCOPE: ContextVar[ScopeEnforcer | None] = ContextVar(
    "talisman_active_scope", default=None
)


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
        with path.open(encoding="utf-8") as stream:
            data = yaml.safe_load(stream) or {}
        if not isinstance(data, dict):
            raise ValueError("Scope file must contain a YAML mapping")

        include = data.get("include", [])
        exclude = data.get("exclude", [])
        restrictions = data.get("restrictions", {}) or {}
        if not isinstance(include, list) or not all(isinstance(x, str) for x in include):
            raise ValueError("'include' must be a list of strings")
        if not isinstance(exclude, list) or not all(isinstance(x, str) for x in exclude):
            raise ValueError("'exclude' must be a list of strings")
        if not isinstance(restrictions, dict):
            raise ValueError("'restrictions' must be a mapping")

        rate = restrictions.get("max_requests_per_second", 50.0)
        if not isinstance(rate, (int, float)) or isinstance(rate, bool) or rate <= 0:
            raise ValueError("'max_requests_per_second' must be a positive number")

        return cls(
            include=include,
            exclude=exclude,
            max_requests_per_second=float(rate),
            avoid_writes=bool(restrictions.get("avoid_writes", False)),
            avoid_destructive=bool(restrictions.get("avoid_destructive", True)),
            respect_robots_txt=bool(restrictions.get("respect_robots_txt", False)),
        )

    @classmethod
    def from_target(cls, target: str) -> "ScopeConfig":
        """Create an exact-host scope; subdomains require explicit authorization."""
        value = target.strip()
        if not value:
            raise ValueError("Target cannot be empty")

        # A CIDR supplied as the target is an explicit network authorization.
        try:
            network = ipaddress.ip_network(value, strict=False)
            return cls(include=[str(network)])
        except ValueError:
            pass

        parsed = urlsplit(value if "://" in value else f"//{value}")
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            raise ValueError(f"Could not determine a valid host from target: {target!r}")
        return cls(include=[host])


class ScopeViolationError(Exception):
    """Raised when a request attempts to access a destination outside the scope."""


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

    @staticmethod
    def _extract_host(target: str) -> str:
        value = target.strip()
        try:
            return str(ipaddress.ip_address(value)).lower()
        except ValueError:
            pass

        parsed = urlsplit(value if "://" in value else f"//{value}")
        return (parsed.hostname or "").lower().rstrip(".")

    @staticmethod
    def _match_pattern(host: str, pattern: str) -> bool:
        pattern = pattern.lower().strip().rstrip(".")
        if not pattern:
            return False
        if pattern.startswith("*."):
            suffix = pattern[2:]
            return host.endswith("." + suffix)
        if "/" in pattern or "://" in pattern or "?" in pattern:
            return False
        return fnmatch(host, pattern) or host == pattern

    @staticmethod
    def _match_cidr(host: str, networks: list) -> bool:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(address in network for network in networks)

    @staticmethod
    def _match_url_pattern(url: str, pattern: str) -> bool:
        """Match URL rules on the same origin and on a path-segment boundary."""
        try:
            candidate = urlsplit(url if "://" in url else f"https://{url}")
            rule = urlsplit(pattern)
        except ValueError:
            return False

        if not rule.scheme or not rule.hostname:
            return False
        if candidate.scheme.lower() != rule.scheme.lower():
            return False
        if (candidate.hostname or "").lower().rstrip(".") != rule.hostname.lower().rstrip("."):
            return False
        try:
            if rule.port is not None and candidate.port != rule.port:
                return False
        except ValueError:
            return False

        rule_path = rule.path or "/"
        candidate_path = candidate.path or "/"
        if "*" in rule_path or "?" in rule_path:
            if not fnmatch(candidate_path, rule_path):
                return False
        elif rule_path != "/" and not (
            candidate_path == rule_path.rstrip("/")
            or candidate_path.startswith(rule_path.rstrip("/") + "/")
        ):
            return False

        if rule.query and candidate.query != rule.query:
            return False
        return True

    def is_in_scope(self, target: str) -> bool:
        host = self._extract_host(target)
        if not host:
            return False
        url = target if "://" in target else f"https://{target}"

        in_scope = any(self._match_pattern(host, pattern) for pattern in self.config.include)
        if not in_scope:
            in_scope = self._match_cidr(host, self._include_nets)
        if not in_scope:
            in_scope = any(
                self._match_url_pattern(url, pattern)
                for pattern in self.config.include
                if "://" in pattern
            )
        if not in_scope:
            log.debug("out_of_scope", target=target)
            return False

        excluded = any(self._match_pattern(host, pattern) for pattern in self.config.exclude)
        if not excluded:
            excluded = self._match_cidr(host, self._exclude_nets)
        if not excluded:
            excluded = any(
                self._match_url_pattern(url, pattern)
                for pattern in self.config.exclude
                if "://" in pattern
            )
        if excluded:
            log.debug("excluded_scope", target=target)
            return False
        return True

    def filter_targets(self, targets: list[str]) -> list[str]:
        return [target for target in targets if self.is_in_scope(target)]

    def assert_in_scope(self, target: str) -> None:
        if not self.is_in_scope(target):
            raise ScopeViolationError(f"Target '{target}' is out of scope")


def get_active_scope() -> ScopeEnforcer | None:
    """Return the scope bound to the current async execution context, if any."""
    return _ACTIVE_SCOPE.get()


def activate_scope(scope: ScopeEnforcer) -> None:
    """Bind a scope to the current async context (used by CLI command setup)."""
    _ACTIVE_SCOPE.set(scope)


@contextmanager
def scope_context(scope: ScopeEnforcer) -> Iterator[None]:
    """Temporarily bind a scope; useful for library callers and regression tests."""
    token = _ACTIVE_SCOPE.set(scope)
    try:
        yield
    finally:
        _ACTIVE_SCOPE.reset(token)
