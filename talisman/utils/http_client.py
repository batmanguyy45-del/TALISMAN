"""
Async HTTP client — compatible with httpx 0.27+ and 0.28+.
Handles proxy, retry, UA rotation, rate limiting.
"""
from __future__ import annotations
import asyncio
import random
import time
from typing import Any
import httpx
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
    """
    Build httpx.AsyncClient compatible with both httpx 0.27.x and 0.28.x.
    httpx 0.28 removed the 'proxies' kwarg — now uses 'proxy' (single string).
    """
    import httpx as _httpx

    kwargs: dict[str, Any] = {
        "timeout": _httpx.Timeout(timeout),
        "verify": verify_ssl,
        "follow_redirects": follow_redirects,
        "headers": headers,
    }

    # Proxy: httpx 0.28+ uses 'proxy' (str), older used 'proxies' (dict)
    if proxy:
        try:
            # httpx 0.28+: single proxy string
            return _httpx.AsyncClient(proxy=proxy, **kwargs)
        except TypeError:
            # Fallback for httpx < 0.27
            return _httpx.AsyncClient(proxies={"all://": proxy}, **kwargs)

    # HTTP/2 support only if h2 is installed
    if _has_h2():
        kwargs["http2"] = True

    return _httpx.AsyncClient(**kwargs)


class TalismanHTTPClient:
    def __init__(
        self,
        proxy: str | None = None,
        timeout: int = 30,
        max_retries: int = 3,
        rotate_ua: bool = True,
        verify_ssl: bool = False,
        follow_redirects: bool = True,
        headers: dict[str, str] | None = None,
        rate_limit: float = 0.0,
    ):
        self.proxy = proxy
        self.timeout = timeout
        self.max_retries = max_retries
        self.rotate_ua = rotate_ua
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.custom_headers = headers or {}
        self.rate_limit = rate_limit
        self._last_request_time: float = 0.0
        self._client: httpx.AsyncClient | None = None
        self._request_count = 0
        self._error_count = 0

    def _make_headers(self) -> dict[str, str]:
        h = {**BROWSER_HEADERS, **self.custom_headers}
        if self.rotate_ua:
            h["User-Agent"] = random.choice(USER_AGENTS)
        return h

    def _build_client(self) -> httpx.AsyncClient:
        return _build_httpx_client(
            proxy=self.proxy,
            timeout=self.timeout,
            verify_ssl=self.verify_ssl,
            follow_redirects=self.follow_redirects,
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
            if self.rate_limit > elapsed:
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
    ) -> httpx.Response:
        await self._enforce_rate_limit()

        if self._client is None:
            self._client = self._build_client()

        req_headers: dict[str, str] = {}
        if self.rotate_ua:
            req_headers["User-Agent"] = random.choice(USER_AGENTS)
        if headers:
            req_headers.update(headers)

        follow = allow_redirects if allow_redirects is not None else self.follow_redirects
        req_timeout = httpx.Timeout(timeout or self.timeout)

        last_exc: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                response = await self._client.request(
                    method=method.upper(),
                    url=url,
                    headers=req_headers,
                    params=params,
                    data=data,
                    json=json,
                    content=content,
                    follow_redirects=follow,
                    timeout=req_timeout,
                )
                self._request_count += 1
                return response
            except (httpx.ConnectError, httpx.TimeoutException, httpx.ReadError) as e:
                last_exc = e
                self._error_count += 1
                if attempt < self.max_retries - 1:
                    wait = (2 ** attempt) + random.uniform(0, 1)
                    log.debug("http_retry", url=url[:80], attempt=attempt + 1, error=str(e)[:60])
                    await asyncio.sleep(wait)
            except httpx.HTTPStatusError as e:
                self._request_count += 1
                return e.response
            except Exception as e:
                self._error_count += 1
                log.debug("http_error", url=url[:80], error=str(e)[:80])
                raise

        # exhausted retries
        raise last_exc or RuntimeError(f"All {self.max_retries} retries failed for {url}")

    # ── Convenience methods ────────────────────────────────────────────────────
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
