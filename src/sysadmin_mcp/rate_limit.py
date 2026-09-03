"""Small in-process sliding-window limiter for MCP sessions."""

from __future__ import annotations

import asyncio
from collections import defaultdict, deque
from collections.abc import Callable
from time import monotonic


class RateLimitExceeded(RuntimeError):
    """The caller exhausted its configured request budget."""


class SlidingWindowRateLimiter:
    """Bound calls per key without external state or background tasks."""

    def __init__(
        self,
        max_requests: int = 60,
        window_seconds: float = 60.0,
        *,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        if (
            isinstance(max_requests, bool)
            or not isinstance(max_requests, int)
            or max_requests < 1
            or isinstance(window_seconds, bool)
            or window_seconds <= 0
        ):
            raise ValueError("rate limits must be positive")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._clock = clock
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def acquire(self, key: str) -> None:
        now = self._clock()
        cutoff = now - self.window_seconds
        async with self._lock:
            requests = self._requests[key]
            while requests and requests[0] <= cutoff:
                requests.popleft()
            if len(requests) >= self.max_requests:
                retry_after = max(1, round(requests[0] + self.window_seconds - now))
                raise RateLimitExceeded(
                    f"Rate limit exceeded; retry in approximately {retry_after} seconds"
                )
            requests.append(now)
