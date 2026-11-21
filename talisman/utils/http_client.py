"""Shared async HTTP client with explicit identity, TLS verification and scope checks."""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
from typing import Any
from urllib.parse import urljoin

import httpx

from talisman.engine.scope import ScopeEnforcer, get_active_scope
from talisman.utils.logger import get_logger

log = get_logger(__name__)

DEFAULT_USER_AGENT = "TALISMAN/1.1 (+authorized security testing)"
SAFE_REDIRECT_METHODS = {"GET", "HEAD", "OPTIONS"}
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
FORBIDDEN_CUSTOM_HEADERS = {
    "content-length",
    "transfer-encoding",
    "connection",
    "proxy-connection",
    "proxy-authorization",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
}
HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def _validate_headers(headers: object) -> dict[str, str]:
    if not isinstance(headers, dict):
        raise ValueError("Custom headers must be a mapping of string names to string values")

    validated: dict[str, str] = {}
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise ValueError("HTTP header names and values must be strings")
        if not HEADER_NAME_RE.fullmatch(name) or name.lower() in FORBIDDEN_CUSTOM_HEADERS:
            raise ValueError(f"Invalid or restricted HTTP header: {name!r}")
        if "\r" in value or "\n" in value:
            raise ValueError(f"HTTP header value contains a line break: {name!r}")
        validated[name] = value
    return validated


def _load_extra_headers() -> dict[str, str]:
    """Load explicitly configured research headers from environment variables."""
    headers: dict[str, str] = {}
    raw = os.environ.get("TALISMAN_EXTRA_HEADERS", "").strip()
    if raw:
        try:
            if raw.startswith("{"):
                parsed = json.loads(raw)
                headers.update(_validate_headers(parsed))
            else:
                pairs: dict[str, str] = {}
                for pair in raw.split(","):
                    key, separator, value = pair.partition(":")
                    if separator:
                        pairs[key.strip()] = value.strip()
                headers.update(_validate_headers(pairs))
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"Invalid TALISMAN_EXTRA_HEADERS: {exc}") from exc

    researcher = os.environ.get("TALISMAN_H1_USERNAME", "").strip()
    if researcher:
        headers["X-HackerOne-Research"] = researcher
    return headers


def _has_h2() -> bool:
    try:
        import h2  # noqa: F401

        return True
    except ImportError:
        return False


def _build_httpx_client(
    proxy: str | None,
    timeout: int,
    verify_ssl: bool,
    headers: dict[str, str],
) -> httpx.AsyncClient:
    """Build an httpx client without implicit redirect handling."""
    kwargs: dict[str, Any] = {
        "timeout": httpx.Timeout(timeout),
        "verify": verify_ssl,
        "follow_redirects": False,
        "headers": headers,
    }
    if proxy:
        try:
            return httpx.AsyncClient(proxy=proxy, **kwargs)
        except TypeError:
            # Compatibility for the older httpx proxies= API.
            return httpx.AsyncClient(proxies={"all://": proxy}, **kwargs)
    if _has_h2():
        kwargs["http2"] = True
    return httpx.AsyncClient(**kwargs)


class TalismanHTTPClient:
    """HTTP client that blocks out-of-scope destinations before connecting.

    Redirects are disabled by default. When explicitly enabled, only safe
    methods are followed and every redirect destination is checked again.
    """

    def __init__(
        self,
        proxy: str | None = None,
        timeout: int = 30,
        max_retries: int = 3,
        rotate_ua: bool = False,
        verify_ssl: bool = True,
        follow_redirects: bool = False,
        headers: dict[str, str] | None = None,
        rate_limit: float = 0.0,
        scope: ScopeEnforcer | None = None,
        max_redirects: int = 5,
    ):
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if max_retries < 1:
            raise ValueError("max_retries must be at least 1")
        if max_redirects < 0:
            raise ValueError("max_redirects cannot be negative")
        if rate_limit < 0:
            raise ValueError("rate_limit cannot be negative")

        self.proxy = proxy
        self.timeout = timeout
        self.max_retries = max_retries
        # Kept for API compatibility. TALISMAN no longer rotates browser UAs.
        self.rotate_ua = False
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.custom_headers = _validate_headers(headers or {})
        self.rate_limit = rate_limit
        self.scope = scope
        self.max_redirects = max_redirects
        self._last_request_time = 0.0
        self._rate_lock = asyncio.Lock()
        self._client: httpx.AsyncClient | None = None
        self._request_count = 0
        self._error_count = 0

    def _make_headers(self) -> dict[str, str]:
        headers = {
            "Accept": "*/*",
            "User-Agent": os.environ.get("TALISMAN_USER_AGENT", DEFAULT_USER_AGENT),
        }
        headers.update(self.custom_headers)
        headers.update(_load_extra_headers())
        return headers

    def _build_client(self) -> httpx.AsyncClient:
        # Keep credentials out of httpx's client-wide defaults. Per-request
        # headers are rebuilt in request() so cross-origin redirects can strip
        # every caller-supplied header before the next connection.
        base_headers = {
            "Accept": "*/*",
            "User-Agent": os.environ.get("TALISMAN_USER_AGENT", DEFAULT_USER_AGENT),
        }
        return _build_httpx_client(
            proxy=self.proxy,
            timeout=self.timeout,
            verify_ssl=self.verify_ssl,
            headers=base_headers,
        )

    async def __aenter__(self) -> TalismanHTTPClient:
        self._client = self._build_client()
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _enforce_rate_limit(self) -> None:
        if self.rate_limit <= 0:
            return
        async with self._rate_lock:
            now = time.monotonic()
            delay = self.rate_limit - (now - self._last_request_time)
            if delay > 0:
                await asyncio.sleep(delay)
            self._last_request_time = time.monotonic()

    def _assert_allowed(self, url: str, method: str) -> None:
        scope = self.scope or get_active_scope()
        if scope is not None:
            scope.assert_request_allowed(url, method)

    async def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: Any = None,
        json: Any = None,
        content: bytes | str | None = None,
        allow_redirects: bool | None = None,
        timeout: int | None = None,
    ) -> httpx.Response:
        method = method.upper()
        request_headers = self._make_headers()
        request_headers.update(_validate_headers(headers or {}))
        follow = self.follow_redirects if allow_redirects is None else allow_redirects
        # Automatic redirection of writes is deliberately prohibited.
        follow = bool(follow and method in SAFE_REDIRECT_METHODS)
        request_timeout = httpx.Timeout(timeout if timeout is not None else self.timeout)

        if self._client is None:
            self._client = self._build_client()

        current_url = url
        current_params = params
        for redirect_index in range(self.max_redirects + 1):
            self._assert_allowed(current_url, method)
            attempts = self.max_retries if method in SAFE_REDIRECT_METHODS else 1
            last_exc: Exception | None = None
            response: httpx.Response | None = None

            for attempt in range(attempts):
                active_scope = self.scope or get_active_scope()
                if active_scope is not None:
                    await active_scope.acquire_request_slot()
                await self._enforce_rate_limit()
                try:
                    response = await self._client.request(
                        method=method,
                        url=current_url,
                        headers=request_headers,
                        params=current_params,
                        data=data,
                        json=json,
                        content=content,
                        follow_redirects=False,
                        timeout=request_timeout,
                    )
                    self._request_count += 1
                    break
                except (httpx.ConnectError, httpx.TimeoutException, httpx.ReadError) as exc:
                    self._error_count += 1
                    last_exc = exc
                    if attempt + 1 < attempts:
                        delay = min(2 ** attempt, 8)
                        log.debug(
                            "http_retry",
                            url=current_url[:120],
                            attempt=attempt + 1,
                            error=type(exc).__name__,
                        )
                        await asyncio.sleep(delay)
                except Exception as exc:
                    self._error_count += 1
                    log.debug(
                        "http_error",
                        url=current_url[:120],
                        error=type(exc).__name__,
                    )
                    raise

            if response is None:
                raise last_exc or RuntimeError(f"HTTP request failed for {current_url}")

            if not follow or response.status_code not in REDIRECT_STATUSES:
                return response
            location = response.headers.get("location")
            if not location:
                return response
            if redirect_index >= self.max_redirects:
                log.warning("http_redirect_limit", url=current_url[:120])
                return response

            next_url = urljoin(str(response.url), location)
            # Check scope before the next connection; never delegate this to httpx.
            self._assert_allowed(next_url, method)
            old_origin = httpx.URL(str(response.url))
            new_origin = httpx.URL(next_url)
            if (old_origin.scheme, old_origin.host, old_origin.port) != (
                new_origin.scheme, new_origin.host, new_origin.port
            ):
                # Credentials and cookies must not cross origin boundaries.
                # On a cross-origin redirect, retain only generic negotiation
                # headers. Custom API keys, cookies, Host overrides, and any
                # future credential header must never leak to the new origin.
                request_headers = {
                    key: value for key, value in request_headers.items()
                    if key.lower() in {"accept", "accept-encoding", "accept-language", "user-agent"}
                }
            current_url = next_url
            current_params = None

        raise RuntimeError("Redirect handling ended unexpectedly")

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("DELETE", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("OPTIONS", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("HEAD", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PATCH", url, **kwargs)

    @property
    def stats(self) -> dict[str, int]:
        return {"requests": self._request_count, "errors": self._error_count}


async def fetch(url: str, method: str = "GET", **kwargs: Any) -> httpx.Response:
    """One-shot request helper."""
    async with TalismanHTTPClient() as client:
        return await client.request(method, url, **kwargs)
