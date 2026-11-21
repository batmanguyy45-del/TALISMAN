"""Strict target-scope parsing and enforcement for outbound requests."""
from __future__ import annotations

import asyncio
import ipaddress
import time
import math
import posixpath
import re
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from urllib.parse import SplitResult, unquote, urlsplit

import yaml

from talisman.utils.logger import get_logger

log = get_logger(__name__)
MAX_REQUESTS_PER_SECOND = 20.0

# Hosts used only as passive data providers by built-in modules. Custom providers
# must be added explicitly to the scope file's service_allowlist.
DEFAULT_SERVICE_HOSTS = (
    "crt.sh",
    "api.hackertarget.com",
    "web.archive.org",
    "ipinfo.io",
    "services.nvd.nist.gov",
    "api.github.com",
    "raw.githubusercontent.com",
    "github.com",
    "dns.google",
    "*.oast.pro",
    "oast.pro",
    "*.interactsh.com",
    "interactsh.com",
    "*.s3.amazonaws.com",
    "registry.npmjs.org",
    "psbdmp.ws",
    "api.shodan.io",
    "internetdb.shodan.io",
    "api.censys.io",
    "search.censys.io",
    "otx.alienvault.com",
    "urlscan.io",
)

_ACTIVE_SCOPE: ContextVar[ScopeEnforcer | None] = ContextVar(
    "talisman_active_scope", default=None
)


def set_active_scope(scope: ScopeEnforcer) -> Token[ScopeEnforcer | None]:
    """Set the scope enforced by HTTP clients in the current async context."""
    return _ACTIVE_SCOPE.set(scope)


def reset_active_scope(token: Token[ScopeEnforcer | None]) -> None:
    """Restore the previous scope after an assessment."""
    _ACTIVE_SCOPE.reset(token)


def get_active_scope() -> ScopeEnforcer | None:
    """Return the scope active in the current async context, if any."""
    return _ACTIVE_SCOPE.get()


def _string_list(value: object, field_name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"Scope field '{field_name}' must be a list of strings")
    return [item.strip() for item in value if item.strip()]


def _normalize_host(host: str) -> str:
    host = host.strip().rstrip(".").lower()
    if not host:
        return ""
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        pass
    try:
        normalized = host.encode("idna").decode("ascii")
    except UnicodeError:
        return ""

    if len(normalized) > 253:
        return ""
    label_re = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    labels = normalized.split(".")
    if any(not label_re.fullmatch(label) for label in labels):
        return ""
    return normalized


def _parse_url(value: str) -> SplitResult | None:
    raw = value.strip()
    if not raw or "\\" in raw or any(ord(char) < 0x21 or ord(char) == 0x7F for char in raw):
        return None
    if "://" not in raw:
        raw = f"https://{raw}"
    try:
        parsed = urlsplit(raw)
        if parsed.scheme.lower() not in {"http", "https"}:
            return None
        if (
            not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or "%" in parsed.hostname
        ):
            return None
        # Accessing .port validates malformed and out-of-range ports.
        _ = parsed.port
        host = _normalize_host(parsed.hostname)
        if not host:
            return None
        netloc = f"[{host}]" if ":" in host else host
        if parsed.port is not None:
            netloc = f"{netloc}:{parsed.port}"
        return SplitResult(
            parsed.scheme.lower(),
            netloc,
            parsed.path or "/",
            parsed.query,
            "",
        )
    except (ValueError, UnicodeError):
        return None


@dataclass
class ScopeConfig:
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    service_allowlist: list[str] = field(default_factory=lambda: list(DEFAULT_SERVICE_HOSTS))
    max_requests_per_second: float = 2.0
    avoid_writes: bool = False
    allow_state_changing_requests: bool = False
    avoid_destructive: bool = True
    respect_robots_txt: bool = False

    @classmethod
    def from_file(cls, path: Path) -> ScopeConfig:
        with path.open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        if not isinstance(data, dict):
            raise ValueError("Scope file must contain a YAML mapping")

        include = _string_list(data.get("include"), "include")
        if not include:
            raise ValueError("Scope file must define at least one 'include' target")
        exclude = _string_list(data.get("exclude"), "exclude")
        services = _string_list(
            data.get("service_allowlist", list(DEFAULT_SERVICE_HOSTS)),
            "service_allowlist",
        )
        restrictions = data.get("restrictions") or {}
        if not isinstance(restrictions, dict):
            raise ValueError("Scope field 'restrictions' must be a mapping")

        rate = restrictions.get("max_requests_per_second", 2.0)
        if isinstance(rate, bool):
            raise ValueError("max_requests_per_second must be numeric, not boolean")
        try:
            rate = float(rate)
        except (TypeError, ValueError) as exc:
            raise ValueError("max_requests_per_second must be a positive number") from exc
        if not math.isfinite(rate) or rate <= 0 or rate > MAX_REQUESTS_PER_SECOND:
            raise ValueError(
                f"max_requests_per_second must be positive and no greater than {MAX_REQUESTS_PER_SECOND:g}"
            )

        def boolean_option(name: str, default: bool) -> bool:
            value = restrictions.get(name, default)
            if not isinstance(value, bool):
                raise ValueError(f"restrictions.{name} must be true or false")
            return value

        return cls(
            include=include,
            exclude=exclude,
            service_allowlist=services,
            max_requests_per_second=rate,
            avoid_writes=boolean_option("avoid_writes", False),
            allow_state_changing_requests=boolean_option("allow_state_changing_requests", False),
            avoid_destructive=boolean_option("avoid_destructive", True),
            respect_robots_txt=boolean_option("respect_robots_txt", False),
        )

    @classmethod
    def from_target(cls, target: str) -> ScopeConfig:
        """Create a scope for one host or explicitly supplied IP network."""
        raw = target.strip()
        try:
            network = ipaddress.ip_network(raw, strict=False)
            return cls(include=[str(network)])
        except ValueError:
            pass

        if raw.startswith("*."):
            wildcard_host = _normalize_host(raw[2:])
            if not wildcard_host:
                raise ValueError(f"Invalid wildcard target: {target!r}")
            return cls(include=[f"*.{wildcard_host}"])

        parsed = _parse_url(raw)
        if parsed is None:
            raise ValueError(f"Invalid target: {target!r}")
        host = _normalize_host(parsed.hostname or "")
        return cls(include=[host])


class ScopeEnforcer:
    """Fail-closed host and URL scope checks used before outbound requests."""

    def __init__(self, config: ScopeConfig):
        if not config.include:
            raise ValueError("At least one in-scope target is required")
        if (
            not math.isfinite(config.max_requests_per_second)
            or config.max_requests_per_second <= 0
            or config.max_requests_per_second > MAX_REQUESTS_PER_SECOND
        ):
            raise ValueError(
                f"max_requests_per_second must be positive and no greater than {MAX_REQUESTS_PER_SECOND:g}"
            )
        self._validate_entries(config.include, "include", allow_url=True)
        self._validate_entries(config.exclude, "exclude", allow_url=True)
        self._validate_entries(config.service_allowlist, "service_allowlist", allow_url=False)
        self.config = config
        self._request_lock = asyncio.Lock()
        self._next_request_at = 0.0
        self._include_nets = self._parse_networks(config.include)
        self._exclude_nets = self._parse_networks(config.exclude)


    @staticmethod
    def _validate_entries(entries: list[str], field_name: str, allow_url: bool) -> None:
        for entry in entries:
            if not isinstance(entry, str) or not entry.strip():
                raise ValueError(f"Invalid empty target in scope field '{field_name}'")
            value = entry.strip()
            try:
                ipaddress.ip_network(value, strict=False)
                continue
            except ValueError:
                pass
            if value.startswith("*."):
                if not _normalize_host(value[2:]):
                    raise ValueError(f"Invalid wildcard target in '{field_name}': {entry!r}")
                continue
            if allow_url and ("://" in value or "/" in value or "?" in value):
                if _parse_url(value) is None:
                    raise ValueError(f"Invalid URL target in '{field_name}': {entry!r}")
                continue
            if not _normalize_host(value):
                raise ValueError(f"Invalid host target in '{field_name}': {entry!r}")

    @staticmethod
    def _parse_networks(
        entries: list[str],
    ) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for entry in entries:
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                continue
        return networks

    @staticmethod
    def _host_matches(host: str, pattern: str) -> bool:
        normalized = pattern.strip().lower()
        if normalized.startswith("*."):
            suffix = _normalize_host(normalized[2:])
            return bool(suffix and host.endswith("." + suffix))
        normalized = _normalize_host(normalized)
        return bool(normalized and fnmatchcase(host, normalized))

    @staticmethod
    def _matches_network(host: str, networks: list) -> bool:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(address.version == network.version and address in network for network in networks)

    @staticmethod
    def _url_pattern_matches(candidate: SplitResult, pattern: str) -> bool:
        expected = _parse_url(pattern)
        if expected is None:
            return False
        if "://" in pattern and candidate.scheme != expected.scheme:
            return False

        candidate_host = _normalize_host(candidate.hostname or "")
        expected_host = _normalize_host(expected.hostname or "")
        if not ScopeEnforcer._host_matches(candidate_host, expected_host):
            # URL patterns may also use a wildcard host.
            if not ScopeEnforcer._host_matches(candidate_host, expected.hostname or ""):
                return False

        if expected.port is not None and candidate.port != expected.port:
            return False

        expected_path = expected.path or "/"
        candidate_path = candidate.path or "/"

        # Decode repeatedly before applying path rules. This prevents common
        # encoded/double-encoded dot-segment and slash tricks from evading an
        # exclusion. Reject backslashes because proxies and frameworks disagree
        # on whether they are path separators.
        for _ in range(3):
            decoded = unquote(candidate_path)
            if decoded == candidate_path:
                break
            candidate_path = decoded
        if "\\" in candidate_path:
            return False
        candidate_path = posixpath.normpath(candidate_path)
        if not candidate_path.startswith("/"):
            candidate_path = "/" + candidate_path

        expected_path = posixpath.normpath(expected_path)
        if not expected_path.startswith("/"):
            expected_path = "/" + expected_path

        if "*" in expected_path or "?" in expected_path:
            if not fnmatchcase(candidate_path, expected_path):
                return False
        elif expected_path != "/" and not (
            candidate_path == expected_path
            or candidate_path.startswith(expected_path.rstrip("/") + "/")
        ):
            return False

        if expected.query and candidate.query != expected.query:
            return False
        return True

    def _matches_entry(self, target: str, entry: str, networks: list) -> bool:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            network = None

        parsed = _parse_url(target)
        if parsed is None:
            return False
        host = _normalize_host(parsed.hostname or "")
        if network is not None:
            try:
                address = ipaddress.ip_address(host)
                return address.version == network.version and address in network
            except ValueError:
                return False

        if "://" in entry or "/" in entry or "?" in entry:
            return self._url_pattern_matches(parsed, entry)

        return self._host_matches(host, entry) or self._matches_network(host, networks)

    def is_in_scope(self, target: str) -> bool:
        if not any(self._matches_entry(target, entry, self._include_nets) for entry in self.config.include):
            log.debug("out_of_scope", target=target)
            return False

        for entry in self.config.exclude:
            if self._matches_entry(target, entry, self._exclude_nets):
                log.debug("excluded_scope", target=target, pattern=entry)
                return False
        return True

    def is_service_allowed(self, target: str) -> bool:
        parsed = _parse_url(target)
        if parsed is None:
            return False
        host = _normalize_host(parsed.hostname or "")
        for entry in self.config.service_allowlist:
            if self._host_matches(host, entry):
                return True
        return False

    async def acquire_request_slot(self) -> None:
        """Apply one shared per-assessment request rate across all HTTP clients."""
        interval = 1.0 / self.config.max_requests_per_second
        async with self._request_lock:
            now = time.monotonic()
            delay = self._next_request_at - now
            if delay > 0:
                await asyncio.sleep(delay)
                now = time.monotonic()
            self._next_request_at = max(now, self._next_request_at) + interval

    def assert_in_scope(self, target: str) -> None:
        if not self.is_in_scope(target):
            raise ScopeViolationError(f"Target '{target}' is out of scope")

    def assert_request_allowed(self, target: str, method: str = "GET") -> None:
        if not (self.is_in_scope(target) or self.is_service_allowed(target)):
            raise ScopeViolationError(
                f"Request blocked: '{target}' is neither in target scope nor an approved service"
            )

        method = method.upper()
        if method not in {"GET", "HEAD", "OPTIONS"}:
            if self.config.avoid_writes or not self.config.allow_state_changing_requests:
                raise ScopeViolationError(
                    f"{method} blocked: enable allow_state_changing_requests in the scope file only when the program permits active testing"
                )
            if method == "DELETE" and self.config.avoid_destructive:
                raise ScopeViolationError(
                    "DELETE blocked: destructive requests are disabled by this scope"
                )

    def filter_targets(self, targets: list[str]) -> list[str]:
        return [target for target in targets if self.is_in_scope(target)]


class ScopeViolationError(Exception):
    """Raised when a target is out of scope."""
