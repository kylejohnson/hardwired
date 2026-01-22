"""Logging utilities for hardwired library."""

import logging
import time
from contextvars import ContextVar, Token

# NullHandler on root logger (library best practice)
_root = logging.getLogger("hardwired")
_root.addHandler(logging.NullHandler())

# Context variable for domain tracking in concurrent operations
_current_domains: ContextVar[list[str] | None] = ContextVar("current_domains", default=None)


def set_domains(domains: list[str] | None) -> Token[list[str] | None]:
    """Set current domains for logging context.

    Args:
        domains: List of domains being processed.

    Returns:
        Token to reset the context.
    """
    return _current_domains.set(domains)


def reset_domains(token: Token[list[str] | None]) -> None:
    """Reset domains context.

    Args:
        token: Token from set_domains() call.
    """
    _current_domains.reset(token)


def get_domain_extra() -> dict[str, list[str] | str]:
    """Get domain info for log extra fields.

    Returns:
        Dict with 'domain' (single) or 'domains' (multiple), or empty dict.
    """
    domains = _current_domains.get()
    if domains is None:
        return {}
    if len(domains) == 1:
        return {"domain": domains[0]}
    return {"domains": domains}


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
