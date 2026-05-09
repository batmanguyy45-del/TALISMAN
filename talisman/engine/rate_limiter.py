"""Token-bucket rate limiter with per-domain tracking and jitter."""
from __future__ import annotations
import asyncio
import random
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional

@dataclass
class RateProfile:
    name: str
    requests_per_second: float
    jitter_factor: float        # 0.0-1.0; gaussian spread
    base_delay_ms: int          # ms between requests
    max_delay_ms: int
    max_concurrent: int

RATE_PROFILES: dict[str, RateProfile] = {
    "aggressive": RateProfile("aggressive", 200.0, 0.10,   0,   50,  50),
    "normal":     RateProfile("normal",      50.0, 0.20, 100,  300,  20),
    "stealth":    RateProfile("stealth",     10.0, 0.40, 500, 2000,   5),
    "passive":    RateProfile("passive",      5.0, 0.50,1000, 5000,   2),
}

class TokenBucket:
    def __init__(self, rate: float, capacity: float | None = None):
        self.rate = rate
        self.capacity = capacity or rate
        self._tokens: float = self.capacity
        self._last_refill: float = time.monotonic()
        self._lock = asyncio.Lock()

    async def consume(self, tokens: float = 1.0) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            self._last_refill = now
            if self._tokens < tokens:
                wait = (tokens - self._tokens) / self.rate
                await asyncio.sleep(wait)
                self._tokens = 0.0
            else:
                self._tokens -= tokens


class RateLimiter:
    def __init__(self, profile: str | RateProfile = "normal"):
        if isinstance(profile, str):
            self._profile = RATE_PROFILES.get(profile, RATE_PROFILES["normal"])
        else:
            self._profile = profile
        self._global_bucket = TokenBucket(self._profile.requests_per_second)
        self._domain_buckets: dict[str, TokenBucket] = defaultdict(
            lambda: TokenBucket(self._profile.requests_per_second / 2)
        )
        self._semaphore = asyncio.Semaphore(self._profile.max_concurrent)

    async def acquire(self, domain: str | None = None) -> None:
        await self._global_bucket.consume()
        if domain:
            await self._domain_buckets[domain].consume()
        delay_ms = random.gauss(
            self._profile.base_delay_ms,
            self._profile.base_delay_ms * self._profile.jitter_factor
        )
        delay_ms = max(0, min(delay_ms, self._profile.max_delay_ms))
        if delay_ms > 0:
            await asyncio.sleep(delay_ms / 1000.0)

    async def __aenter__(self) -> "RateLimiter":
        await self._semaphore.acquire()
        return self

    async def __aexit__(self, *args: object) -> None:
        self._semaphore.release()

    @property
    def profile(self) -> RateProfile:
        return self._profile
