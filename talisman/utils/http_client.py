"""
Async HTTP client with centralized scope enforcement.
All scan requests inherit the active scope bound by the CLI. Auxiliary lookups
against third-party intelligence services must opt out explicitly per client
or request; target traffic must never do so.
"""
from __future__ import annotations

import asyncio
import json
import os
import random
import time
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from talisman.engine.scope import ScopeViolationError, get_active_scope
from talisman.utils.logger import get_logger

log = get_logger(__name__)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]

BROWSER_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
}
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_MAX_REDIRECT_HOPS = 10


def _load_extra_headers() -> dict[str, str]:
    """Load custom headers from environment variables."""
    headers: dict[str, str] = {}
    raw = os.environ.get("TALISMAN_EXTRA_HEADERS", "").strip()
    if raw:
        if raw.startswith("{"):
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    headers.update(
                        {str(key): str(value) for key, value in parsed.items()}
                    )
            except json.JSONDecodeError:
                log.warning("invalid_extra_headers_json")
        else:
            for pair in raw.split(","):
                pair = pair.strip()
                if ":" in pair:
                    key, value = pair.split(":", 1)
                    headers[key.strip()] = value.strip()

    h1 = os.environ.get("TALISMAN_H1_USERNAME", "").strip()
    if h1:
        headers["X-HackerOne-Research"] = h1
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
    follow_redirects: bool,
    headers: dict[str, str],
) -> httpx.AsyncClient:
    """Build an httpx client compatible with supported 0.27+ releases."""
    kwargs: dict[str, Any] = {
        "timeout": httpx.Timeout(timeout),
        "verify": verify_ssl,
        # Redirects are handled below so every hop is checked before dispatch.
        "follow_redirects": False,
        "headers": headers,
    }
    if proxy:
        try:
            return httpx.AsyncClient(proxy=proxy, **kwargs)
        except TypeError:
            return httpx.AsyncClient(proxies={"all://": proxy}, **kwargs)

    if _has_h2():
        kwargs["http2"] = True
    return httpx.AsyncClient(**kwargs)


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    try:
        port = parsed.port
    except ValueError:
        return scheme, host, -1
    if port is None:
        port = 443 if scheme == "https" else 80 if scheme == "http" else None
    return scheme, host, port


def _safe_redirect_origin(source: str, destination: str) -> bool:
    """Only follow same-origin redirects, plus a same-host HTTP-to-HTTPS upgrade."""
    source_origin = _origin(source)
    destination_origin = _origin(destination)
    if source_origin == destination_origin:
        return True

    source_scheme, source_host, source_port = source_origin
    dest_scheme, dest_host, dest_port = destination_origin
    return (
        source_scheme == "http"
        and dest_scheme == "https"
        and source_host == dest_host
        and source_port in (None, 80)
        and dest_port in (None, 443)
    )


class TalismanHTTPClient:
    def __init__(
        self,
        proxy: str | None = None,
        timeout: int = 30,
        max_retries: int = 3,
        rotate_ua: bool = True,
        verify_ssl: bool = True,
        follow_redirects: bool = True,
        headers: dict[str, str] | None = None,
        rate_limit: float = 0.0,
        scope_exempt: bool = False,
    ):
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if max_retries < 1:
            raise ValueError("max_retries must be at least 1")
        if rate_limit < 0:
            raise ValueError("rate_limit cannot be negative")

        self.proxy = proxy
        self.timeout = timeout
        self.max_retries = max_retries
        self.rotate_ua = rotate_ua
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.custom_headers = headers or {}
        self.rate_limit = rate_limit
        self.scope_exempt = scope_exempt
        self._last_request_time: float = 0.0
        self._client: httpx.AsyncClient | None = None
        self._request_count = 0
        self._error_count = 0

    def _make_headers(self) -> dict[str, str]:
        headers = {**BROWSER_HEADERS, **self.custom_headers, **_load_extra_headers()}
        if self.rotate_ua:
            headers["User-Agent"] = random.choice(USER_AGENTS)
        return headers

    def _build_client(self) -> httpx.AsyncClient:
        return _build_httpx_client(
            proxy=self.proxy,
            timeout=self.timeout,
            verify_ssl=self.verify_ssl,
            follow_redirects=False,
            headers=self._make_headers(),
        )

    async def __aenter__(self) -> "TalismanHTTPClient":
        self._client = self._build_client()
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _enforce_rate_limit(self) -> None:
        if self.rate_limit > 0:
            now = time.monotonic()
            elapsed = now - self._last_request_time
            if elapsed < self.rate_limit:
                await asyncio.sleep(self.rate_limit - elapsed)
        self._last_request_time = time.monotonic()

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
        scope_exempt: bool = False,
    ) -> httpx.Response:
        scope = None if (self.scope_exempt or scope_exempt) else get_active_scope()
        if scope is not None:
            try:
                scope.assert_in_scope(url)
            except ScopeViolationError:
                log.warning("out_of_scope_request_blocked", url=url)
                raise

        await self._enforce_rate_limit()
        if self._client is None:
            self._client = self._build_client()

        request_headers: dict[str, str] = {}
        if self.rotate_ua:
            request_headers["User-Agent"] = random.choice(USER_AGENTS)
        if headers:
            request_headers.update(headers)

        follow = allow_redirects if allow_redirects is not None else self.follow_redirects
        request_timeout = httpx.Timeout(timeout or self.timeout)
        request_method = method.upper()
        request_url = url
        request_data, request_json, request_content = data, json, content

        last_exc: Exception | None = None
        response: httpx.Response | None = None
        for attempt in range(self.max_retries):
            try:
                response = await self._client.request(
                    method=request_method,
                    url=request_url,
                    headers=request_headers,
                    params=params,
                    data=request_data,
                    json=request_json,
                    content=request_content,
                    follow_redirects=False,
                    timeout=request_timeout,
                )
                self._request_count += 1
                break
            except (httpx.ConnectError, httpx.TimeoutException, httpx.ReadError) as exc:
                last_exc = exc
                self._error_count += 1
                if attempt < self.max_retries - 1:
                    wait = (2 ** attempt) + random.uniform(0, 1)
                    log.debug(
                        "http_retry", url=request_url[:80],
                        attempt=attempt + 1, error=str(exc)[:60],
                    )
                    await asyncio.sleep(wait)
            except Exception as exc:
                self._error_count += 1
                log.debug("http_error", url=request_url[:80], error=str(exc)[:80])
                raise

        if response is None:
            raise last_exc or RuntimeError(f"All {self.max_retries} retries failed for {url}")

        # Follow only redirects that remain on the same origin (or safely upgrade
        # HTTP to HTTPS). Cross-origin redirects are returned to the caller and
        # never receive the original request's headers or credentials.
        if follow:
            current_url = str(response.url)
            for _ in range(_MAX_REDIRECT_HOPS):
                if response.status_code not in _REDIRECT_STATUSES:
                    break
                location = response.headers.get("location")
                if not location:
                    break
                next_url = urljoin(current_url, location)

                if scope is not None:
                    try:
                        scope.assert_in_scope(next_url)
                    except ScopeViolationError:
                        log.warning("redirect_out_of_scope_blocked", url=current_url, destination=next_url)
                        break

                if not _safe_redirect_origin(current_url, next_url):
                    log.warning("cross_origin_redirect_blocked", url=current_url, destination=next_url)
                    break

                if response.status_code == 303 or (
                    response.status_code in (301, 302) and request_method not in ("GET", "HEAD")
                ):
                    request_method = "GET"
                    request_data = request_json = request_content = None

                try:
                    response = await self._client.request(
                        method=request_method,
                        url=next_url,
                        headers=request_headers,
                        follow_redirects=False,
                        timeout=request_timeout,
                        data=request_data,
                        json=request_json,
                        content=request_content,
                    )
                    self._request_count += 1
                    current_url = str(response.url)
                except (httpx.ConnectError, httpx.TimeoutException, httpx.ReadError):
                    self._error_count += 1
                    break

        return response

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
