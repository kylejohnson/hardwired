"""Pytest fixtures for Hardwired test suite."""

import contextlib
import logging
import logging.handlers
import os
import ssl
import warnings
from collections.abc import Generator
from pathlib import Path

import httpx
import pytest

# Suppress InsecureRequestWarning for pebble bootstrap
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Default URLs for local pebble setup
PEBBLE_DIRECTORY_URL = os.environ.get("PEBBLE_DIRECTORY_URL", "https://localhost:14000/dir")
PEBBLE_MGMT_URL = os.environ.get("PEBBLE_MGMT_URL", "https://localhost:15000")
CHALLTESTSRV_URL = os.environ.get("CHALLTESTSRV_URL", "http://localhost:8055")

# Default URLs for local PowerDNS setup
POWERDNS_API_URL = os.environ.get("POWERDNS_API_URL", "http://localhost:8081")
POWERDNS_API_KEY = os.environ.get("POWERDNS_API_KEY", "test-api-key")


@pytest.fixture(scope="session")
def pebble_ca_cert() -> str | bool:
    """Get SSL verification setting for Pebble.

    Returns False to disable SSL verification for pebble tests.
    Pebble uses a self-signed certificate that's not meant for production.

    If PEBBLE_CA_CERT env var is set, returns that path instead.
    """
    # First try to get from environment variable
    ca_cert_path = os.environ.get("PEBBLE_CA_CERT")
    if ca_cert_path and Path(ca_cert_path).exists():
        return ca_cert_path

    # For pebble testing, disable SSL verification
    # Pebble's TLS cert is intentionally insecure for testing
    return False


@pytest.fixture(scope="session")
def pebble_ssl_context(pebble_ca_cert: str) -> ssl.SSLContext:
    """Create an SSL context that trusts the Pebble CA."""
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(pebble_ca_cert)
    return ctx


@pytest.fixture(scope="session")
def pebble_directory_url() -> str:
    """Return the Pebble ACME directory URL."""
    return PEBBLE_DIRECTORY_URL


@pytest.fixture(scope="session")
def challtestsrv_url() -> str:
    """Return the pebble-challtestsrv management API URL."""
    return CHALLTESTSRV_URL


@pytest.fixture(scope="session")
def pebble_http_client(pebble_ca_cert: str) -> Generator[httpx.Client]:
    """Create an httpx client that trusts the Pebble CA."""
    client = httpx.Client(verify=pebble_ca_cert)
    yield client
    client.close()


@pytest.fixture(scope="session")
def powerdns_api_url() -> str:
    """Return the PowerDNS API URL."""
    return POWERDNS_API_URL


@pytest.fixture(scope="session")
def powerdns_api_key() -> str:
    """Return the PowerDNS API key."""
    return POWERDNS_API_KEY


@pytest.fixture(scope="session", autouse=False)
def powerdns_test_zone(powerdns_api_url: str, powerdns_api_key: str) -> Generator[str]:
    """Create a test zone in PowerDNS for integration tests.

    This fixture creates the example.org zone via the PowerDNS API
    and cleans it up after all tests complete.
    """
    zone_name = "example.org."
    headers = {
        "X-API-Key": powerdns_api_key,
        "Content-Type": "application/json",
    }

    # Create the zone
    zone_data = {
        "name": zone_name,
        "kind": "Native",
        "nameservers": ["ns1.example.org."],
        "soa_edit_api": "DEFAULT",
    }

    try:
        response = httpx.post(
            f"{powerdns_api_url}/api/v1/servers/localhost/zones",
            headers=headers,
            json=zone_data,
            timeout=30,
        )
        # 201 = created, 409 = already exists (which is fine)
        if response.status_code not in (201, 409):
            response.raise_for_status()
    except httpx.ConnectError:
        pytest.skip("PowerDNS not available")

    yield zone_name

    # Cleanup: delete the zone (best effort)
    with contextlib.suppress(httpx.HTTPError):
        httpx.delete(
            f"{powerdns_api_url}/api/v1/servers/localhost/zones/{zone_name}",
            headers=headers,
            timeout=30,
        )


class LogCapture:
    """Helper class to capture and inspect log records."""

    def __init__(self, handler: logging.handlers.MemoryHandler) -> None:
        self._handler = handler

    @property
    def records(self) -> list[logging.LogRecord]:
        """Get all captured log records."""
        return self._handler.buffer

    def get_records(
        self, level: int | None = None, name: str | None = None
    ) -> list[logging.LogRecord]:
        """Get log records filtered by level and/or logger name.

        Args:
            level: Filter by log level (e.g., logging.INFO).
            name: Filter by logger name prefix (e.g., "hardwired.client").

        Returns:
            List of matching log records.
        """
        records = self.records
        if level is not None:
            records = [r for r in records if r.levelno == level]
        if name is not None:
            records = [r for r in records if r.name.startswith(name)]
        return records

    def get_messages(self, level: int | None = None, name: str | None = None) -> list[str]:
        """Get log messages filtered by level and/or logger name.

        Args:
            level: Filter by log level (e.g., logging.INFO).
            name: Filter by logger name prefix (e.g., "hardwired.client").

        Returns:
            List of log message strings.
        """
        return [r.getMessage() for r in self.get_records(level, name)]

    def clear(self) -> None:
        """Clear all captured log records."""
        self._handler.buffer.clear()


@pytest.fixture
def log_capture() -> Generator[LogCapture]:
    """Capture logs from the hardwired library during a test.

    Usage:
        def test_something(log_capture):
            # do something that logs
            assert "Certificate issued" in log_capture.get_messages(logging.INFO)
    """
    # Create a memory handler to capture logs
    handler = logging.handlers.MemoryHandler(capacity=1000)
    handler.setLevel(logging.DEBUG)

    # Attach to the hardwired root logger
    hardwired_logger = logging.getLogger("hardwired")
    original_level = hardwired_logger.level
    hardwired_logger.setLevel(logging.DEBUG)
    hardwired_logger.addHandler(handler)

    try:
        yield LogCapture(handler)
    finally:
        hardwired_logger.removeHandler(handler)
        hardwired_logger.setLevel(original_level)
        handler.close()
