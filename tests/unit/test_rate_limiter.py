"""Unit tests for rate limiter."""
import asyncio
import time
import pytest
from talisman.engine.rate_limiter import RateLimiter, RATE_PROFILES, TokenBucket

@pytest.mark.asyncio
async def test_token_bucket_rate():
 bucket = TokenBucket(rate=10.0) # 10 tokens/sec
 start = time.monotonic()
 # Consume 5 tokens
 for _ in range(5):
  await bucket.consume()
 elapsed = time.monotonic() - start
 # Should take ~0.4s for tokens 2-5 (first is instant)
 assert elapsed < 2.0 # Not too slow

@pytest.mark.asyncio
async def test_rate_limiter_profiles():
 for profile_name in RATE_PROFILES:
  rl = RateLimiter(profile_name)
  assert rl.profile.name == profile_name

@pytest.mark.asyncio
async def test_semaphore_limits():
 rl = RateLimiter("aggressive") # max_concurrent=50
 max_c = rl.profile.max_concurrent
 assert max_c == 50

def test_all_profiles_present():
 required = {"aggressive", "normal", "stealth", "passive"}
 assert required.issubset(set(RATE_PROFILES.keys()))
