# Hardwired

A Python library for automated SSL/TLS certificate management via the ACME protocol (RFC 8555).

## Installation

```bash
pip install hardwired
```

## Quick Start

```python
from hardwired import AcmeClient
from hardwired.crypto import generate_rsa_key
from hardwired.providers.test import TestProvider

# Generate an account key
account_key = generate_rsa_key(2048)

# Initialize client with DNS provider
client = AcmeClient(
    directory_url="https://acme-v02.api.letsencrypt.org/directory",
    account_key=account_key,
    dns_provider=TestProvider(challtestsrv_url="http://localhost:8055"),
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
uv run ty             # Type check
```
