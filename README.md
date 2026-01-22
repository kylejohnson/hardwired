# Hardwired

A Python library for automated SSL/TLS certificate management via the ACME protocol (RFC 8555).

## Installation

```bash
pip install hardwired
```

Or with [uv](https://docs.astral.sh/uv/):

```bash
uv add hardwired
```

## Quick Start

```python
from hardwired import AcmeClient
from hardwired.crypto import generate_rsa_key
from hardwired.providers import PowerDnsProvider

# Generate an account key
account_key = generate_rsa_key(2048)

# Initialize client with your DNS provider
client = AcmeClient(
    directory_url="https://acme-v02.api.letsencrypt.org/directory",
    account_key=account_key,
    dns_provider=PowerDnsProvider(
        api_url="http://your-powerdns-server:8081",
        api_key="your-api-key",
    ),
)

# Register account
account = client.register_account(email="admin@example.com")

# Obtain certificate
cert = client.obtain_certificate(
    domains=["example.com", "*.example.com"],
)

# Access results
print(cert.certificate_pem)    # Full certificate chain
print(cert.private_key_pem)    # Private key (if CSR was auto-generated)
print(cert.expires_at)         # Expiration timestamp
```

## Features

- Full RFC 8555 (ACME) compliance
- DNS-01 challenge support
- Pluggable DNS provider architecture
- Type hints on all public APIs
- Structured logging with hierarchical loggers

## Logging

Hardwired uses Python's standard logging module with a hierarchical logger structure. By default, the library is silent (using `NullHandler`). Configure logging to see output:

```python
import logging

# Basic: INFO level to console
logging.basicConfig(level=logging.INFO)

# See all operations (verbose)
logging.getLogger("hardwired").setLevel(logging.DEBUG)

# Debug only DNS provider operations
logging.getLogger("hardwired.providers").setLevel(logging.DEBUG)
```

### Logger Hierarchy

| Logger | Purpose |
|--------|---------|
| `hardwired` | Root logger |
| `hardwired.client` | ACME client operations |
| `hardwired.providers.powerdns` | PowerDNS provider |
| `hardwired.providers.pebble` | Pebble test provider |
| `hardwired.exceptions` | Rate limit warnings |

### Structured Logging

All log calls include structured `extra` fields for machine-readable output:

```python
from pythonjsonlogger import jsonlogger

handler = logging.StreamHandler()
handler.setFormatter(jsonlogger.JsonFormatter())
logging.getLogger("hardwired").addHandler(handler)
logging.getLogger("hardwired").setLevel(logging.INFO)
```

Example output:
```json
{"message": "Certificate issued", "domains": ["example.com"], "expires_at": "2024-04-15T12:00:00Z"}
```

## DNS Providers

Hardwired uses DNS providers to manage TXT records for DNS-01 challenge validation.

| Provider | Use Case | Documentation |
|----------|----------|---------------|
| PowerDNS | Production - self-hosted PowerDNS | [Setup Guide](docs/providers/powerdns.md) |
| Pebble | Testing only | [Setup Guide](docs/providers/pebble.md) |

See the [Provider Documentation](docs/providers/README.md) for details on configuring providers or [implementing your own](docs/providers/custom.md).

## Development

### Setup

```bash
# Install dependencies
uv sync --all-extras

# Start test infrastructure
docker compose -f docker-compose.test.yml up -d

# Run tests
uv run pytest

# Run with coverage
uv run pytest --cov=hardwired --cov-report=term-missing
```

### Code Quality

```bash
uv run ruff format    # Format code
uv run ruff check     # Lint code
uv run ty check       # Type check
```
