# PowerDNS Provider

The PowerDNS provider manages DNS TXT records for ACME DNS-01 challenges via the [PowerDNS Authoritative Server HTTP API](https://doc.powerdns.com/authoritative/http-api/index.html).

## Prerequisites

- PowerDNS Authoritative Server 4.x or later
- HTTP API enabled on your PowerDNS server
- An API key configured
- At least one zone configured that covers your domain(s)

## Installation

The PowerDNS provider is included with Hardwired:

```bash
pip install hardwired
```

## Configuration

### Constructor Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `api_url` | str | Yes | - | Base URL of the PowerDNS API (e.g., `http://localhost:8081`) |
| `api_key` | str | Yes | - | API key for authentication |
| `server_id` | str | No | `"localhost"` | PowerDNS server identifier |
| `timeout` | int | No | `30` | HTTP request timeout in seconds |

### Environment Variables Pattern

For production deployments, consider loading credentials from environment variables:

```python
import os
from hardwired.providers import PowerDnsProvider

provider = PowerDnsProvider(
    api_url=os.environ["POWERDNS_API_URL"],
    api_key=os.environ["POWERDNS_API_KEY"],
)
```

## PowerDNS Server Setup

### 1. Enable the HTTP API

Add these settings to your PowerDNS configuration (`pdns.conf`):

```ini
# Enable the web server
webserver=yes
webserver-address=0.0.0.0
webserver-port=8081
webserver-allow-from=127.0.0.1,::1

# Enable the API
api=yes
api-key=your-secret-api-key
```

### 2. Create an API Key

Generate a secure API key:

```bash
# Generate a random API key
openssl rand -hex 32
```

Add the key to your `pdns.conf`:

```ini
api-key=your-generated-api-key
```

### 3. Restart PowerDNS

```bash
systemctl restart pdns
```

### 4. Verify API Access

```bash
curl -H "X-API-Key: your-api-key" http://localhost:8081/api/v1/servers/localhost
```

## Zone Requirements

The provider automatically discovers the correct zone for your domain. Your PowerDNS server must have a zone configured that covers the domain(s) you're requesting certificates for.

For example, to get a certificate for `www.example.com`:
- You need a zone for `example.com` (or a parent zone)
- The provider will create `_acme-challenge.www.example.com` in the `example.com` zone

## Usage Example

### Basic Usage

```python
from hardwired import AcmeClient
from hardwired.crypto import generate_rsa_key
from hardwired.providers import PowerDnsProvider

# Configure the provider
provider = PowerDnsProvider(
    api_url="http://your-powerdns-server:8081",
    api_key="your-api-key",
)

# Create the ACME client
client = AcmeClient(
    directory_url="https://acme-v02.api.letsencrypt.org/directory",
    account_key=generate_rsa_key(2048),
    dns_provider=provider,
)

# Register and obtain certificate
client.register_account(email="admin@example.com")
cert = client.obtain_certificate(domains=["example.com", "*.example.com"])

print(cert.certificate_pem)
print(cert.private_key_pem)
```

### With Persistent Account Key

```python
from pathlib import Path
from cryptography.hazmat.primitives import serialization

from hardwired import AcmeClient
from hardwired.crypto import generate_rsa_key
from hardwired.providers import PowerDnsProvider

# Load or create account key
key_path = Path("account.key")
if key_path.exists():
    account_key = serialization.load_pem_private_key(
        key_path.read_bytes(),
        password=None,
    )
else:
    account_key = generate_rsa_key(2048)
    key_path.write_bytes(
        account_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

# Configure and use
provider = PowerDnsProvider(
    api_url="http://powerdns:8081",
    api_key="secret",
)

client = AcmeClient(
    directory_url="https://acme-v02.api.letsencrypt.org/directory",
    account_key=account_key,
    dns_provider=provider,
)
```

## How It Works

### Zone Discovery

When creating a TXT record, the provider:

1. Fetches all zones from the PowerDNS API
2. Iterates through domain levels (e.g., `sub.example.com` -> `example.com`)
3. Returns the first matching zone

### Record Creation

The provider creates TXT records using the PowerDNS API:

- **Endpoint**: `PATCH /api/v1/servers/{server_id}/zones/{zone}`
- **Record name**: `_acme-challenge.{domain}.`
- **TTL**: 60 seconds
- **Change type**: `REPLACE` (creates or updates)

### Record Deletion

After challenge validation, the provider removes the TXT record:

- **Endpoint**: `PATCH /api/v1/servers/{server_id}/zones/{zone}`
- **Change type**: `DELETE`

### Propagation

Since PowerDNS updates are synchronous (the API returns 204 on success), the `wait_for_propagation()` method returns immediately. The record is available as soon as the API call succeeds.

## Troubleshooting

### Connection Refused

```
httpx.ConnectError: [Errno 111] Connection refused
```

**Cause**: Cannot connect to the PowerDNS API.

**Solutions**:
- Verify PowerDNS is running: `systemctl status pdns`
- Check `api_url` is correct
- Verify `webserver` and `api` are enabled in `pdns.conf`
- Check firewall rules allow access to the API port

### Authentication Failed (401/403)

```
httpx.HTTPStatusError: 401 Unauthorized
```

**Cause**: Invalid or missing API key.

**Solutions**:
- Verify `api_key` matches `api-key` in `pdns.conf`
- Ensure the `X-API-Key` header is being sent
- Check `webserver-allow-from` includes your client's IP

### No Zone Found

```
ValueError: No zone found for domain: example.com
```

**Cause**: No PowerDNS zone covers the requested domain.

**Solutions**:
- List zones: `curl -H "X-API-Key: key" http://localhost:8081/api/v1/servers/localhost/zones`
- Create the zone if missing
- Verify the domain hierarchy matches an existing zone

### Record Creation Failed (422)

```
httpx.HTTPStatusError: 422 Unprocessable Entity
```

**Cause**: Invalid record data sent to PowerDNS.

**Solutions**:
- Check PowerDNS logs: `journalctl -u pdns`
- Verify the zone exists and is writable
- Ensure the record name is valid

## API Reference

### `PowerDnsProvider`

```python
class PowerDnsProvider(DnsProvider):
    def __init__(
        self,
        api_url: str,
        api_key: str,
        server_id: str = "localhost",
        timeout: int = 30,
    ): ...
```

### Methods

#### `create_txt_record(domain: str, token: str) -> None`

Creates a TXT record at `_acme-challenge.{domain}` with the challenge token.

**Raises**:
- `ValueError`: If no zone is found for the domain
- `httpx.HTTPStatusError`: If the API request fails

#### `delete_txt_record(domain: str, token: str) -> None`

Deletes the TXT record at `_acme-challenge.{domain}`.

**Raises**:
- `ValueError`: If no zone is found for the domain
- `httpx.HTTPStatusError`: If the API request fails

#### `wait_for_propagation(domain: str, token: str, timeout: int = 120) -> bool`

Returns `True` immediately since PowerDNS updates are synchronous.

## See Also

- [PowerDNS HTTP API Documentation](https://doc.powerdns.com/authoritative/http-api/index.html)
- [Provider Overview](README.md)
- [Custom Provider Guide](custom.md)
