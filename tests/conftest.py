"""Pytest fixtures for Hardwired test suite."""

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
