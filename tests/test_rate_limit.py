import pytest

from sysadmin_mcp.rate_limit import RateLimitExceeded, SlidingWindowRateLimiter


@pytest.mark.asyncio
async def test_sliding_window_denies_then_recovers() -> None:
    now = [100.0]
    limiter = SlidingWindowRateLimiter(2, 10, clock=lambda: now[0])
    await limiter.acquire("session")
    await limiter.acquire("session")

    with pytest.raises(RateLimitExceeded, match="retry"):
        await limiter.acquire("session")

    now[0] = 110.0
    await limiter.acquire("session")


@pytest.mark.asyncio
async def test_rate_budgets_are_isolated_by_key() -> None:
    limiter = SlidingWindowRateLimiter(1, 60)
    await limiter.acquire("alice")
    await limiter.acquire("bob")
    with pytest.raises(RateLimitExceeded):
        await limiter.acquire("alice")


@pytest.mark.parametrize(
    "args", [(0, 60), (-1, 60), (True, 60), (1, 0), (1, -1)]
)
def test_invalid_rate_limits_are_rejected(args) -> None:
    with pytest.raises(ValueError, match="positive"):
        SlidingWindowRateLimiter(*args)
