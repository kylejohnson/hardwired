# Custom Provider Guide

This guide walks you through implementing a custom DNS provider for Hardwired. By the end, you'll have a working provider that integrates with any DNS service.

## Overview

DNS providers in Hardwired implement a simple interface with three methods:

1. `create_txt_record()` - Create the challenge TXT record
2. `delete_txt_record()` - Clean up after validation
3. `wait_for_propagation()` - Wait for DNS to propagate (optional)

## The DnsProvider Interface

All providers inherit from the `DnsProvider` abstract base class:

```python
from abc import ABC, abstractmethod

class DnsProvider(ABC):
    """Abstract interface for DNS providers."""

    @abstractmethod
    def create_txt_record(self, domain: str, token: str) -> None:
        """Create a TXT record for ACME challenge.

        Creates a TXT record at _acme-challenge.{domain} with the
        provided token value.

        Args:
            domain: The domain name (without _acme-challenge prefix).
            token: The challenge token value to set as TXT record.

        Raises:
            Exception: If record creation fails.
        """
        ...

    @abstractmethod
    def delete_txt_record(self, domain: str, token: str) -> None:
        """Delete a TXT record for ACME challenge.

        Removes the TXT record at _acme-challenge.{domain}.

        Args:
            domain: The domain name (without _acme-challenge prefix).
            token: The challenge token value (for providers that need it).

        Raises:
            Exception: If record deletion fails.
        """
        ...

    @abstractmethod
    def wait_for_propagation(self, domain: str, token: str, timeout: int = 120) -> bool:
        """Wait for DNS propagation.

        Waits until the TXT record is visible via DNS queries.

        Args:
            domain: The domain name.
            token: The expected token value.
            timeout: Maximum time to wait in seconds.

        Returns:
            True if the record propagated successfully, False if timeout.
        """
        ...
```

## Step-by-Step Implementation

Let's implement a provider for a hypothetical DNS service called "ExampleDNS".

### Step 1: Create the Provider File

Create a new file `src/hardwired/providers/exampledns.py`:

```python
"""ExampleDNS provider for ACME DNS-01 challenges."""

import httpx

from hardwired.providers.base import DnsProvider


class ExampleDnsProvider(DnsProvider):
    """DNS provider for ExampleDNS service.

    Args:
        api_url: Base URL of the ExampleDNS API.
        api_token: Authentication token for the API.
        timeout: HTTP request timeout in seconds.
    """

    def __init__(
        self,
        api_url: str,
        api_token: str,
        timeout: int = 30,
    ):
        self.api_url = api_url.rstrip("/")
        self.api_token = api_token
        self.timeout = timeout

    def create_txt_record(self, domain: str, token: str) -> None:
        """Create a TXT record via ExampleDNS API."""
        record_name = f"_acme-challenge.{domain}"

        response = httpx.post(
            f"{self.api_url}/dns/records",
            headers={"Authorization": f"Bearer {self.api_token}"},
            json={
                "type": "TXT",
                "name": record_name,
                "content": token,
                "ttl": 60,
            },
            timeout=self.timeout,
        )
        response.raise_for_status()

    def delete_txt_record(self, domain: str, token: str) -> None:
        """Delete a TXT record via ExampleDNS API."""
        record_name = f"_acme-challenge.{domain}"

        # First, find the record ID
        response = httpx.get(
            f"{self.api_url}/dns/records",
            headers={"Authorization": f"Bearer {self.api_token}"},
            params={"name": record_name, "type": "TXT"},
            timeout=self.timeout,
        )
        response.raise_for_status()

        records = response.json()
        for record in records:
            if record["content"] == token:
                # Delete the matching record
                httpx.delete(
                    f"{self.api_url}/dns/records/{record['id']}",
                    headers={"Authorization": f"Bearer {self.api_token}"},
                    timeout=self.timeout,
                ).raise_for_status()
                return

    def wait_for_propagation(self, domain: str, token: str, timeout: int = 120) -> bool:
        """Wait for DNS propagation.

        For most authoritative DNS servers, updates are synchronous.
        Return True immediately unless you need to verify propagation.
        """
        return True
```

### Step 2: Handle Zone Discovery (If Needed)

Some DNS APIs require you to specify the zone (e.g., `example.com`) separately from the record name. Here's how to implement zone discovery:

```python
def _find_zone(self, domain: str) -> str:
    """Find the zone that contains the given domain."""
    # Fetch all zones from the API
    response = httpx.get(
        f"{self.api_url}/dns/zones",
        headers={"Authorization": f"Bearer {self.api_token}"},
        timeout=self.timeout,
    )
    response.raise_for_status()

    zones = {z["name"] for z in response.json()}

    # Try each domain level (sub.example.com -> example.com -> com)
    parts = domain.split(".")
    for i in range(len(parts)):
        candidate = ".".join(parts[i:])
        if candidate in zones:
            return candidate

    raise ValueError(f"No zone found for domain: {domain}")
```

### Step 3: Implement DNS Propagation Check (Optional)

If your provider needs to verify DNS propagation before returning:

```python
import time
import dns.resolver  # Requires: pip install dnspython

def wait_for_propagation(self, domain: str, token: str, timeout: int = 120) -> bool:
    """Wait for DNS propagation by querying DNS."""
    record_name = f"_acme-challenge.{domain}"
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        try:
            answers = dns.resolver.resolve(record_name, "TXT")
            for rdata in answers:
                # TXT records are returned as quoted strings
                txt_value = str(rdata).strip('"')
                if txt_value == token:
                    return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except dns.resolver.LifetimeTimeout:
            pass

        time.sleep(2)

    return False
```

### Step 4: Export Your Provider

Add your provider to `src/hardwired/providers/__init__.py`:

```python
"""DNS providers for ACME challenge validation."""

from hardwired.providers.base import DnsProvider
from hardwired.providers.pebble import PebbleProvider
from hardwired.providers.powerdns import PowerDnsProvider
from hardwired.providers.exampledns import ExampleDnsProvider  # Add this

__all__ = [
    "DnsProvider",
    "PebbleProvider",
    "PowerDnsProvider",
    "ExampleDnsProvider",  # Add this
]
```

## Testing Your Provider

### Unit Tests

Create unit tests that don't require the actual DNS service:

```python
# tests/unit/test_exampledns_provider.py

from hardwired.providers.base import DnsProvider
from hardwired.providers.exampledns import ExampleDnsProvider


class TestExampleDnsProviderInterface:
    """Tests for ExampleDnsProvider interface compliance."""

    def test_provider_implements_interface(self):
        """Provider should implement DnsProvider interface."""
        provider = ExampleDnsProvider(
            api_url="http://localhost:8080",
            api_token="test-token",
        )
        assert isinstance(provider, DnsProvider)

    def test_provider_has_required_methods(self):
        """Provider should have all required methods."""
        provider = ExampleDnsProvider(
            api_url="http://localhost:8080",
            api_token="test-token",
        )
        assert callable(provider.create_txt_record)
        assert callable(provider.delete_txt_record)
        assert callable(provider.wait_for_propagation)


class TestExampleDnsProvider:
    """Unit tests for ExampleDnsProvider configuration."""

    def test_provider_stores_configuration(self):
        """Provider should store configuration."""
        provider = ExampleDnsProvider(
            api_url="http://api.example.com",
            api_token="my-token",
            timeout=60,
        )
        assert provider.api_url == "http://api.example.com"
        assert provider.api_token == "my-token"
        assert provider.timeout == 60

    def test_api_url_trailing_slash_stripped(self):
        """Provider should strip trailing slash from API URL."""
        provider = ExampleDnsProvider(
            api_url="http://api.example.com/",
            api_token="token",
        )
        assert provider.api_url == "http://api.example.com"
```

### Integration Tests

Create integration tests that run against a real (or mock) service:

```python
# tests/integration/test_exampledns_provider.py

import pytest
from hardwired.providers.exampledns import ExampleDnsProvider


@pytest.fixture
def exampledns_provider() -> ExampleDnsProvider:
    """Create provider for integration tests."""
    return ExampleDnsProvider(
        api_url="http://localhost:8080",
        api_token="test-token",
    )


class TestExampleDnsProviderIntegration:
    """Integration tests for ExampleDnsProvider."""

    def test_create_and_delete_dns_record(self, exampledns_provider):
        """Should create and delete DNS TXT records."""
        domain = "test.example.com"
        token = "test-token-123"

        exampledns_provider.create_txt_record(domain, token)
        exampledns_provider.delete_txt_record(domain, token)

    def test_create_subdomain_record(self, exampledns_provider):
        """Should create records for subdomains."""
        domain = "sub.test.example.com"
        token = "subdomain-token"

        exampledns_provider.create_txt_record(domain, token)
        exampledns_provider.delete_txt_record(domain, token)
```

## Best Practices

### Error Handling

- Use `raise_for_status()` to convert HTTP errors to exceptions
- Raise `ValueError` for configuration errors (e.g., zone not found)
- Let `httpx` exceptions propagate for network errors

### Authentication

- Support environment variables for credentials
- Never log or expose API keys
- Use HTTPS for API communication

### Record Management

- Always use the full record name: `_acme-challenge.{domain}`
- Set a low TTL (60 seconds) for challenge records
- Clean up records after validation completes

### Propagation

- If your DNS service updates synchronously, return `True` immediately
- If updates take time, implement polling with exponential backoff
- Respect the timeout parameter

## Example Providers

For reference implementations, see:

- [PowerDNS Provider](../src/hardwired/providers/powerdns.py) - Production provider with zone discovery
- [Pebble Provider](../src/hardwired/providers/pebble.py) - Simple test provider

## See Also

- [Provider Overview](README.md)
- [PowerDNS Provider](powerdns.md)
- [DnsProvider Base Class](../src/hardwired/providers/base.py)
