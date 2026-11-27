"""
src/vulnflow/orchestrator/retry.py
Retry helpers with exponential backoff and jitter for resilient execution.
"""

from __future__ import annotations

import functools
import logging
import random
import time
from typing import Any, Callable, Tuple, Type, TypeVar

logger = logging.getLogger("vulnflow.orchestrator.retry")

T = TypeVar("T")


def retry_with_backoff(
    func: Callable[..., T],
    *args: Any,
    max_retries: int = 3,
    base_delay: float = 0.05,
    max_delay: float = 1.0,
    factor: float = 2.0,
    retryable_exceptions: Tuple[Type[Exception], ...] = (Exception,),
    **kwargs: Any,
) -> T:
    """
    Execute a callable with exponential backoff retry on transient failures.
    """
    delay = base_delay
    last_exc: Exception | None = None

    for attempt in range(1, max_retries + 1):
        try:
            return func(*args, **kwargs)
        except retryable_exceptions as exc:
            last_exc = exc
            if attempt == max_retries:
                logger.error("Exceeded %d retries for %s: %s", max_retries, func.__name__, exc)
                raise
            jitter = random.uniform(0.8, 1.2)
            sleep_time = min(delay * jitter, max_delay)
            logger.warning(
                "Attempt %d/%d failed for %s (%s). Retrying in %.2fs...",
                attempt,
                max_retries,
                func.__name__,
                exc,
                sleep_time,
            )
            time.sleep(sleep_time)
            delay *= factor

    if last_exc:
        raise last_exc
    raise RuntimeError(f"Unexpected termination in retry loop for {func.__name__}")


def with_retry(
    max_retries: int = 3,
    base_delay: float = 0.05,
    max_delay: float = 1.0,
    factor: float = 2.0,
    retryable_exceptions: Tuple[Type[Exception], ...] = (Exception,),
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator applying exponential backoff retry to target function."""

    def decorator(fn: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            return retry_with_backoff(
                fn,
                *args,
                max_retries=max_retries,
                base_delay=base_delay,
                max_delay=max_delay,
                factor=factor,
                retryable_exceptions=retryable_exceptions,
                **kwargs,
            )

        return wrapper

    return decorator
