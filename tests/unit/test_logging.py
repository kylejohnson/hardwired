"""Unit tests for logging functionality."""

import logging

import pytest

from hardwired._logging import (
    Timer,
    get_domain_extra,
    get_logger,
    reset_domains,
    set_domains,
)


class TestGetLogger:
    """Tests for the get_logger function."""

    def test_returns_logger_with_hardwired_namespace(self) -> None:
        """Verify logger is under hardwired namespace."""
        logger = get_logger("hardwired.client")
        assert logger.name == "hardwired.client"

    def test_logger_hierarchy(self) -> None:
        """Verify logger hierarchy is correct."""
        parent = logging.getLogger("hardwired")
        child = get_logger("hardwired.client")
        assert child.parent is parent


class TestTimer:
    """Tests for the Timer context manager."""

    def test_measures_elapsed_time(self) -> None:
        """Verify Timer measures elapsed time in milliseconds."""
        import time

        with Timer() as t:
            time.sleep(0.01)  # Sleep 10ms

        # Should be at least 10ms (allow some tolerance)
        assert t.elapsed_ms >= 9
        # Should be reasonable (less than 100ms for a 10ms sleep)
        assert t.elapsed_ms < 100

    def test_elapsed_starts_at_zero(self) -> None:
        """Verify elapsed_ms is 0 before context exit."""
        timer = Timer()
        assert timer.elapsed_ms == 0


class TestNullHandler:
    """Tests for NullHandler setup (library best practice)."""

    def test_root_logger_has_null_handler(self) -> None:
        """Verify NullHandler is attached to root logger."""
        # Import the module to trigger handler setup
        import hardwired._logging  # noqa: F401

        root = logging.getLogger("hardwired")
        handler_types = [type(h).__name__ for h in root.handlers]
        assert "NullHandler" in handler_types

    def test_library_silent_by_default(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Verify library is silent without consumer configuration."""
        logger = get_logger("hardwired.test")
        logger.info("This should not appear")

        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""


class TestLogCapture:
    """Tests for the log_capture fixture."""

    def test_captures_debug_messages(self, log_capture) -> None:
        """Verify debug messages are captured."""
        logger = get_logger("hardwired.test")
        logger.debug("Debug message")

        messages = log_capture.get_messages(logging.DEBUG)
        assert "Debug message" in messages

    def test_captures_info_messages(self, log_capture) -> None:
        """Verify info messages are captured."""
        logger = get_logger("hardwired.test")
        logger.info("Info message")

        messages = log_capture.get_messages(logging.INFO)
        assert "Info message" in messages

    def test_captures_warning_messages(self, log_capture) -> None:
        """Verify warning messages are captured."""
        logger = get_logger("hardwired.test")
        logger.warning("Warning message")

        messages = log_capture.get_messages(logging.WARNING)
        assert "Warning message" in messages

    def test_captures_error_messages(self, log_capture) -> None:
        """Verify error messages are captured."""
        logger = get_logger("hardwired.test")
        logger.error("Error message")

        messages = log_capture.get_messages(logging.ERROR)
        assert "Error message" in messages

    def test_filter_by_logger_name(self, log_capture) -> None:
        """Verify filtering by logger name works."""
        client_logger = get_logger("hardwired.client")
        provider_logger = get_logger("hardwired.providers.powerdns")

        client_logger.info("Client message")
        provider_logger.info("Provider message")

        client_messages = log_capture.get_messages(name="hardwired.client")
        assert "Client message" in client_messages
        assert "Provider message" not in client_messages

        provider_messages = log_capture.get_messages(name="hardwired.providers")
        assert "Provider message" in provider_messages
        assert "Client message" not in provider_messages

    def test_extra_fields_captured(self, log_capture) -> None:
        """Verify extra fields are captured in log records."""
        logger = get_logger("hardwired.test")
        logger.info("Test message", extra={"domain": "example.com", "status": "valid"})

        records = log_capture.get_records(logging.INFO)
        assert len(records) == 1
        assert records[0].domain == "example.com"
        assert records[0].status == "valid"

    def test_clear_removes_records(self, log_capture) -> None:
        """Verify clear() removes all captured records."""
        logger = get_logger("hardwired.test")
        logger.info("Message 1")
        logger.info("Message 2")

        assert len(log_capture.records) == 2
        log_capture.clear()
        assert len(log_capture.records) == 0


class TestDomainContext:
    """Tests for domain context variable functions."""

    def test_get_domain_extra_returns_empty_when_no_context(self) -> None:
        """Verify get_domain_extra returns empty dict when no context is set."""
        result = get_domain_extra()
        assert result == {}

    def test_set_domains_single_domain(self) -> None:
        """Verify single domain returns 'domain' key."""
        token = set_domains(["example.com"])
        try:
            result = get_domain_extra()
            assert result == {"domain": "example.com"}
        finally:
            reset_domains(token)

    def test_set_domains_multiple_domains(self) -> None:
        """Verify multiple domains returns 'domains' key."""
        token = set_domains(["example.com", "www.example.com"])
        try:
            result = get_domain_extra()
            assert result == {"domains": ["example.com", "www.example.com"]}
        finally:
            reset_domains(token)

    def test_reset_domains_restores_previous_context(self) -> None:
        """Verify reset_domains properly restores previous context."""
        # Set outer context
        outer_token = set_domains(["outer.com"])
        try:
            # Set inner context
            inner_token = set_domains(["inner.com"])
            assert get_domain_extra() == {"domain": "inner.com"}

            # Reset inner context
            reset_domains(inner_token)
            assert get_domain_extra() == {"domain": "outer.com"}
        finally:
            reset_domains(outer_token)

        # After all resets, should be empty
        assert get_domain_extra() == {}

    def test_set_domains_none_returns_empty(self) -> None:
        """Verify setting domains to None returns empty dict."""
        token = set_domains(None)
        try:
            result = get_domain_extra()
            assert result == {}
        finally:
            reset_domains(token)

    def test_domain_context_in_log_extra(self, log_capture) -> None:
        """Verify domain context integrates with log extra fields."""
        logger = get_logger("hardwired.test")
        token = set_domains(["test.example.com"])
        try:
            logger.info("Test message", extra={**get_domain_extra()})
        finally:
            reset_domains(token)

        records = log_capture.get_records(logging.INFO)
        assert len(records) == 1
        assert records[0].domain == "test.example.com"

    def test_domain_context_with_other_extra_fields(self, log_capture) -> None:
        """Verify domain context merges with other extra fields."""
        logger = get_logger("hardwired.test")
        token = set_domains(["merge.example.com"])
        try:
            logger.info(
                "Test message",
                extra={"url": "https://example.com", **get_domain_extra()},
            )
        finally:
            reset_domains(token)

        records = log_capture.get_records(logging.INFO)
        assert len(records) == 1
        assert records[0].domain == "merge.example.com"
        assert records[0].url == "https://example.com"
