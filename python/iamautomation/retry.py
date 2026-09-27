from __future__ import annotations

import random
import time
from typing import Callable, TypeVar

T = TypeVar("T")


class RateLimitError(RuntimeError):
    """Raised for provider-side 429/rate limit conditions."""


def run_with_exponential_backoff(
    func: Callable[[], T],
    *,
    attempts: int = 5,
    base_delay: float = 0.5,
    max_delay: float = 8.0,
) -> T:
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            return func()
        except RateLimitError as exc:
            last_error = exc
            if attempt == attempts:
                break
            delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
            delay += random.uniform(0.0, 0.25)
            time.sleep(delay)
    if last_error:
        raise last_error
    return func()
