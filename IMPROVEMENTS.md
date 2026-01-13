# Future Improvements

This document tracks potential enhancements for future releases.

## Retry Strategy

**Current**: Fixed 2-second delay with 30 max attempts (60 second max wait).

**Improvement**: Implement exponential backoff for polling challenge and order status.

```python
# Example implementation
def poll_with_backoff(
    check_fn: Callable[[], T],
    initial_delay: float = 1.0,
    max_delay: float = 30.0,
    max_attempts: int = 30,
    backoff_factor: float = 2.0,
) -> T:
    delay = initial_delay
    for attempt in range(max_attempts):
        result = check_fn()
        if result is not None:
            return result
        time.sleep(delay)
        delay = min(delay * backoff_factor, max_delay)
    raise TimeoutError("Polling timed out")
```

**Benefits**:
- Reduces load on ACME server during long waits
- More efficient for challenges that take longer to validate
- Configurable parameters for different use cases

## Additional Improvements

- [ ] Async/await support (httpx supports both sync and async)
- [ ] Connection pooling for high-volume operations
- [ ] Retry on transient network errors
- [ ] Detailed logging with configurable levels
- [ ] Better logging (json)
- [ ] Observability
- [ ] Metrics/instrumentation hooks
