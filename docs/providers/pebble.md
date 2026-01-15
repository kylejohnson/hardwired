# Pebble Provider

The Pebble provider is designed for **testing only**. It works with [pebble-challtestsrv](https://github.com/letsencrypt/pebble/tree/main/cmd/pebble-challtestsrv), a mock DNS server that pairs with the [Pebble ACME server](https://github.com/letsencrypt/pebble) for local development and CI testing.

> **Warning**: Do not use this provider in production. It only works with pebble-challtestsrv and cannot manage real DNS records.

## When to Use

- Local development and testing
- CI/CD pipelines
- Learning how ACME works
- Testing certificate workflows without real DNS

## Prerequisites

- Docker (recommended) or locally installed Pebble
- pebble-challtestsrv running alongside Pebble

## Setup with Docker Compose

The easiest way to run Pebble is with Docker Compose. Create a `docker-compose.yml`:

```yaml
services:
  pebble:
    image: ghcr.io/letsencrypt/pebble:latest
    command: -config /test/config/pebble-config.json -dnsserver challtestsrv:8053
    environment:
      - PEBBLE_VA_NOSLEEP=1
      - PEBBLE_VA_ALWAYS_VALID=0
    ports:
      - "14000:14000"   # ACME server
      - "15000:15000"   # Management interface
    depends_on:
      - challtestsrv

  challtestsrv:
    image: ghcr.io/letsencrypt/pebble-challtestsrv:latest
    command: -dns01 ":8053" -http01 "" -https01 "" -tlsalpn01 ""
    ports:
      - "8055:8055"     # Management API
```

Start the services:

```bash
docker compose up -d
```

## Configuration

### Constructor Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `challtestsrv_url` | str | Yes | - | URL of the pebble-challtestsrv management API |

### Example

```python
from hardwired.providers import PebbleProvider

provider = PebbleProvider(challtestsrv_url="http://localhost:8055")
```

## Usage Example

```python
from hardwired import AcmeClient
from hardwired.crypto import generate_rsa_key
from hardwired.providers import PebbleProvider

# Configure the test provider
provider = PebbleProvider(challtestsrv_url="http://localhost:8055")

# Create ACME client pointing to Pebble (not Let's Encrypt!)
client = AcmeClient(
    directory_url="https://localhost:14000/dir",
    account_key=generate_rsa_key(2048),
    dns_provider=provider,
    ca_cert=False,  # Disable SSL verification for Pebble's self-signed cert
)

# Register and obtain certificate
client.register_account(email="test@example.com")
cert = client.obtain_certificate(domains=["test.example.com"])

print("Certificate obtained!")
print(cert.certificate_pem)
```

## How It Works

The Pebble provider communicates with pebble-challtestsrv via its HTTP management API:

### Record Creation

- **Endpoint**: `POST /set-txt`
- **Payload**: `{"host": "_acme-challenge.example.com.", "value": "token"}`

### Record Deletion

- **Endpoint**: `POST /clear-txt`
- **Payload**: `{"host": "_acme-challenge.example.com."}`

### Propagation

Since pebble-challtestsrv serves DNS responses directly, propagation is instantaneous. The `wait_for_propagation()` method always returns `True` immediately.

## Integration Testing

The Pebble provider is used in Hardwired's own test suite. See the project's `docker-compose.test.yml` for a working configuration:

```bash
# Start test infrastructure
docker compose -f docker-compose.test.yml up -d

# Run tests
uv run pytest tests/integration/
```

## Limitations

- Only works with pebble-challtestsrv
- Cannot create real DNS records
- Certificates issued by Pebble are not trusted by browsers
- Not suitable for production use

## API Reference

### `PebbleProvider`

```python
class PebbleProvider(DnsProvider):
    def __init__(self, challtestsrv_url: str): ...
```

### Methods

#### `create_txt_record(domain: str, token: str) -> None`

Creates a TXT record in pebble-challtestsrv.

#### `delete_txt_record(domain: str, token: str) -> None`

Removes a TXT record from pebble-challtestsrv.

#### `wait_for_propagation(domain: str, token: str, timeout: int = 120) -> bool`

Always returns `True` immediately (no propagation delay).

## See Also

- [Pebble GitHub Repository](https://github.com/letsencrypt/pebble)
- [Provider Overview](README.md)
- [PowerDNS Provider](powerdns.md) - for production use
