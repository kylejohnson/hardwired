"""Logging utilities for hardwired library."""

import logging
import time

# NullHandler on root logger (library best practice)
_root = logging.getLogger("hardwired")
_root.addHandler(logging.NullHandler())


def get_logger(name: str) -> logging.Logger:
    """Get a logger under the hardwired namespace.

    Args:
        name: The module name (typically __name__).

    Returns:
        A logger instance for the module.
    """
    return logging.getLogger(name)


class Timer:
    """Context manager for timing operations.

    Usage:
        with Timer() as t:
            # do work
        print(f"Elapsed: {t.elapsed_ms}ms")
    """

    def __init__(self) -> None:
        self.elapsed_ms: float = 0
        self._start: float = 0

    def __enter__(self) -> "Timer":
        self._start = time.perf_counter()
        return self

    def __exit__(self, *args: object) -> None:
        self.elapsed_ms = (time.perf_counter() - self._start) * 1000
