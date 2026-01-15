# DNS Providers

Hardwired uses a pluggable DNS provider architecture for DNS-01 challenge validation. Providers are responsible for creating and deleting TXT records that prove domain ownership to the ACME server.

## Available Providers

| Provider | Use Case | Authentication | Documentation |
|----------|----------|----------------|---------------|
| [PowerDNS](powerdns.md) | Production - self-hosted PowerDNS | API Key | Full setup guide |
| [Pebble](pebble.md) | Testing only | None | Test setup guide |

## Choosing a Provider

### For Production

**PowerDNS** - If you run your own PowerDNS authoritative DNS server, this provider communicates directly with the PowerDNS HTTP API to manage TXT records.

### For Development/Testing

**Pebble** - Use this provider with the [Pebble ACME server](https://github.com/letsencrypt/pebble) and its challenge test server for local development and CI testing. This provider is **not** for production use.

## Provider Architecture

All providers implement the `DnsProvider` abstract base class:

```python
from abc import ABC, abstractmethod

class DnsProvider(ABC):
    @abstractmethod
    def create_txt_record(self, domain: str, token: str) -> None:
        """Create a TXT record at _acme-challenge.{domain}."""
        ...

    @abstractmethod
    def delete_txt_record(self, domain: str, token: str) -> None:
        """Delete the TXT record at _acme-challenge.{domain}."""
        ...

    @abstractmethod
    def wait_for_propagation(self, domain: str, token: str, timeout: int = 120) -> bool:
        """Wait for the DNS record to propagate. Returns True on success."""
        ...
```

## Basic Usage

```python
from hardwired import AcmeClient
from hardwired.crypto import generate_rsa_key
from hardwired.providers import PowerDnsProvider

# Initialize your DNS provider
dns_provider = PowerDnsProvider(
    api_url="http://your-powerdns-server:8081",
    api_key="your-api-key",
)

# Create the ACME client with your provider
client = AcmeClient(
    directory_url="https://acme-v02.api.letsencrypt.org/directory",
    account_key=generate_rsa_key(2048),
    dns_provider=dns_provider,
)

# The client will automatically use your provider for DNS-01 challenges
cert = client.obtain_certificate(domains=["example.com"])
```

## Implementing a Custom Provider

Need to support a different DNS provider? See our [Custom Provider Guide](custom.md) for step-by-step instructions on implementing your own provider.

## How DNS-01 Challenge Works

1. Client requests a certificate from the ACME server
2. ACME server returns a challenge token for each domain
3. Client creates a TXT record at `_acme-challenge.{domain}` with a computed value
4. Client notifies ACME server the challenge is ready
5. ACME server queries DNS for the TXT record
6. If the record matches, the domain is validated
7. Client cleans up by deleting the TXT record

The DNS provider handles steps 3 and 7 of this process.
