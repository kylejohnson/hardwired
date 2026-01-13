# PRD Phase 1: Core RFC 8555 + DNS-01

## Overview

**Hardwired** is a Python library for automated SSL/TLS certificate management via the ACME protocol. This phase implements the core ACME client with DNS-01 challenge support.

**Primary Use Case**: Integration into a Python application managing SSL certificates for 300k+ domains via Celery task queues.

---

## Phase 1 Goals

- Full RFC 8555 (ACME) compliance for core operations
- DNS-01 challenge implementation
- Pluggable DNS provider architecture
- Test provider for pebble-challtestsrv
- >80% test coverage
- All integration tests passing against pebble

## Non-Goals (This Phase)

- HTTP-01 challenge (Phase 2)
- RFC 9773 renewal information (Phase 3)
- CLI interface
- Celery integration
- Async/await
- PyPI publishing

---

## Development Methodology: Test-Driven Development

**Every feature follows this cycle:**
1. **Write tests first** - Define expected behavior via failing tests
2. **Run tests** - Confirm they fail (red)
3. **Implement code** - Write minimal code to pass tests
4. **Run tests** - Confirm they pass (green)
5. **Refactor** - Clean up while tests stay green

**Completion criteria**: Phase 1 is NOT complete until all tests pass against pebble + pebble-challtestsrv.

---

## Architecture

### File Structure

```
hardwired/
├── pyproject.toml
├── README.md
├── LICENSE
├── docker-compose.test.yml
├── src/
│   └── hardwired/
│       ├── __init__.py
│       ├── py.typed              # PEP 561 marker
│       ├── client.py             # Main AcmeClient class
│       ├── crypto.py             # Key generation, CSR, JWS
│       ├── models.py             # Pydantic models for ACME resources
│       ├── exceptions.py         # Custom exception hierarchy
│       ├── challenges/
│       │   ├── __init__.py
│       │   ├── base.py           # Abstract challenge handler
│       │   └── dns01.py          # DNS-01 implementation
│       └── providers/
│           ├── __init__.py
│           ├── base.py           # Abstract DNS provider interface
│           └── test.py           # Mock provider for pebble-challtestsrv
└── tests/
    ├── __init__.py
    ├── conftest.py               # Pytest fixtures, pebble setup
    ├── unit/
    │   ├── test_crypto.py
    │   ├── test_models.py
    │   ├── test_challenges.py
    │   └── test_providers.py
    └── integration/
        ├── test_provider.py
        ├── test_account.py
        ├── test_order.py
        ├── test_challenges.py
        └── test_certificate.py
```

### DNS Provider Interface

```python
from abc import ABC, abstractmethod

class DnsProvider(ABC):
    @abstractmethod
    def create_txt_record(self, domain: str, token: str) -> None:
        """Create _acme-challenge.{domain} TXT record."""
        ...

    @abstractmethod
    def delete_txt_record(self, domain: str, token: str) -> None:
        """Remove the challenge TXT record."""
        ...

    @abstractmethod
    def wait_for_propagation(self, domain: str, token: str, timeout: int = 120) -> bool:
        """Wait for DNS propagation. Returns True if propagated."""
        ...
```

### Client API

```python
from hardwired import AcmeClient
from hardwired.providers.test import TestProvider

# Initialize client
client = AcmeClient(
    directory_url="https://acme-v02.api.letsencrypt.org/directory",
    account_key=account_key,  # cryptography RSAPrivateKey or EllipticCurvePrivateKey
    dns_provider=TestProvider(),
)

# Register/fetch account
account = client.register_account(email="admin@example.com")

# Request certificate
cert = client.obtain_certificate(
    domains=["example.com", "*.example.com"],
    csr=csr,  # Optional, generated if not provided
)

# Access results
cert.certificate_pem    # str: Full certificate chain
cert.private_key_pem    # str: Private key (if CSR was auto-generated)
cert.expires_at         # datetime: Expiration timestamp
```

---

## Technical Requirements

### Python & Tooling

| Requirement | Specification |
|-------------|---------------|
| Python | >= 3.13 |
| Package manager | `uv` |
| Formatting | `uv run ruff format` |
| Linting | `uv run ruff check` |
| Type checking | `uv run ty` |
| Testing | `pytest` with `pytest-cov` |
| Type hints | Required on all public APIs |

### Dependencies

**Runtime:**
- `httpx` - HTTP client (sync)
- `cryptography` - Key/CSR/certificate handling
- `pydantic` - Data validation and models

**Development:**
- `pytest` - Test framework
- `pytest-cov` - Coverage reporting
- `ruff` - Formatting and linting
- `ty` - Type checking

### Test Infrastructure

```yaml
# docker-compose.test.yml
services:
  pebble:
    image: letsencrypt/pebble
    command: pebble -config /test/config/pebble-config.json
    environment:
      - PEBBLE_VA_NOSLEEP=1
      - PEBBLE_VA_ALWAYS_VALID=0
    ports:
      - "14000:14000"   # ACME server
      - "15000:15000"   # Management interface
    networks:
      - acme-test

  challtestsrv:
    image: letsencrypt/pebble-challtestsrv
    command: pebble-challtestsrv -defaultIPv4 10.30.50.1 -dns01 ":8053" -http01 "" -https01 "" -tlsalpn01 ""
    ports:
      - "8055:8055"     # Management API
    networks:
      acme-test:
        ipv4_address: 10.30.50.1

networks:
  acme-test:
    driver: bridge
    ipam:
      config:
        - subnet: 10.30.50.0/24
```

---

## Implementation Steps (TDD)

### Step 1.1: Project Setup + Test Infrastructure

**Tasks:**
- `uv init` with Python 3.13+
- Configure `pyproject.toml` with dependencies and PyPI-ready metadata
- Set up `docker-compose.test.yml` with pebble + pebble-challtestsrv
- Create `tests/conftest.py` with pebble fixtures
- Create initial empty test files

**pyproject.toml template:**
```toml
[project]
name = "hardwired"
version = "0.1.0"
description = "ACME client library for automated SSL/TLS certificate management"
readme = "README.md"
license = "MIT"
requires-python = ">=3.13"
dependencies = [
    "httpx>=0.27",
    "cryptography>=43.0",
    "pydantic>=2.9",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-cov>=5.0",
    "ruff>=0.7",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/hardwired"]

[tool.ruff]
line-length = 100
target-version = "py313"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "SIM"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-v --tb=short"
```

**Verify:** `docker compose -f docker-compose.test.yml up -d` starts successfully

---

### Step 1.2: Crypto Module (TDD)

| Test First | Then Implement |
|------------|----------------|
| `test_generate_rsa_key_2048()` | RSA 2048-bit key generation |
| `test_generate_rsa_key_4096()` | RSA 4096-bit key generation |
| `test_generate_ecdsa_key_p256()` | ECDSA P-256 key generation |
| `test_generate_ecdsa_key_p384()` | ECDSA P-384 key generation |
| `test_create_csr_single_domain()` | CSR with single domain |
| `test_create_csr_san()` | CSR with SAN (multiple domains) |
| `test_create_csr_wildcard()` | CSR with wildcard domain |
| `test_jws_sign_rsa()` | JWS with RSA key |
| `test_jws_sign_ecdsa()` | JWS with ECDSA key |
| `test_key_thumbprint_rsa()` | Thumbprint for RSA key |
| `test_key_thumbprint_ecdsa()` | Thumbprint for ECDSA key |

**Example test (write first):**
```python
# tests/unit/test_crypto.py
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from hardwired.crypto import generate_rsa_key, generate_ecdsa_key, create_csr, sign_jws, key_thumbprint


def test_generate_rsa_key_2048():
    key = generate_rsa_key(key_size=2048)
    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == 2048


def test_generate_rsa_key_4096():
    key = generate_rsa_key(key_size=4096)
    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == 4096


def test_generate_ecdsa_key_p256():
    key = generate_ecdsa_key(curve="P-256")
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert key.curve.name == "secp256r1"


def test_create_csr_single_domain():
    key = generate_rsa_key(2048)
    csr = create_csr(key, domains=["example.com"])
    # Verify CSR has correct subject and SAN
    assert csr.is_signature_valid
    # Check domain in SAN extension


def test_create_csr_wildcard():
    key = generate_rsa_key(2048)
    csr = create_csr(key, domains=["*.example.com", "example.com"])
    assert csr.is_signature_valid


def test_jws_sign_includes_required_headers():
    key = generate_rsa_key(2048)
    jws = sign_jws(
        key=key,
        payload={"test": "data"},
        url="https://example.com/acme",
        nonce="test-nonce",
    )
    # Verify JWS structure: header.payload.signature
    parts = jws.split(".")
    assert len(parts) == 3


def test_key_thumbprint_is_base64url():
    key = generate_rsa_key(2048)
    thumbprint = key_thumbprint(key)
    # Thumbprint should be base64url encoded SHA-256
    assert len(thumbprint) == 43  # 32 bytes base64url = 43 chars
```

**Verify:** `uv run pytest tests/unit/test_crypto.py -v` - all pass

---

### Step 1.3: Models + Exceptions (TDD)

| Test First | Then Implement |
|------------|----------------|
| `test_directory_model_from_json()` | Directory resource model |
| `test_account_model_from_json()` | Account resource model |
| `test_order_model_from_json()` | Order resource model |
| `test_authorization_model_from_json()` | Authorization resource model |
| `test_challenge_model_from_json()` | Challenge resource model |
| `test_acme_error_parsing()` | AcmeError from JSON response |
| `test_challenge_error_subclass()` | ChallengeError exception |
| `test_order_error_subclass()` | OrderError exception |

**Example test (write first):**
```python
# tests/unit/test_models.py
import pytest
from hardwired.models import Directory, Account, Order, Authorization, Challenge
from hardwired.exceptions import AcmeError, ChallengeError


def test_directory_model_from_json():
    data = {
        "newNonce": "https://example.com/acme/new-nonce",
        "newAccount": "https://example.com/acme/new-acct",
        "newOrder": "https://example.com/acme/new-order",
        "revokeCert": "https://example.com/acme/revoke-cert",
        "keyChange": "https://example.com/acme/key-change",
    }
    directory = Directory.model_validate(data)
    assert directory.new_nonce == "https://example.com/acme/new-nonce"
    assert directory.new_account == "https://example.com/acme/new-acct"


def test_order_model_from_json():
    data = {
        "status": "pending",
        "expires": "2024-01-01T00:00:00Z",
        "identifiers": [{"type": "dns", "value": "example.com"}],
        "authorizations": ["https://example.com/acme/authz/123"],
        "finalize": "https://example.com/acme/order/123/finalize",
    }
    order = Order.model_validate(data)
    assert order.status == "pending"
    assert len(order.identifiers) == 1


def test_challenge_model_dns01():
    data = {
        "type": "dns-01",
        "url": "https://example.com/acme/chall/123",
        "status": "pending",
        "token": "abc123",
    }
    challenge = Challenge.model_validate(data)
    assert challenge.type == "dns-01"
    assert challenge.token == "abc123"


def test_acme_error_parsing():
    error_response = {
        "type": "urn:ietf:params:acme:error:malformed",
        "detail": "Request payload did not parse as JSON",
        "status": 400,
    }
    error = AcmeError.from_response(error_response, status_code=400)
    assert error.type == "urn:ietf:params:acme:error:malformed"
    assert "malformed" in str(error)
```

**Verify:** `uv run pytest tests/unit/test_models.py -v` - all pass

---

### Step 1.4: Test Provider for pebble-challtestsrv (TDD)

| Test First | Then Implement |
|------------|----------------|
| `test_provider_implements_interface()` | TestProvider extends DnsProvider |
| `test_add_dns_record_calls_api()` | POST to challtestsrv /set-txt |
| `test_delete_dns_record_calls_api()` | POST to challtestsrv /clear-txt |
| `test_wait_for_propagation_returns_true()` | Immediate return (no actual DNS) |

**Example test (write first):**
```python
# tests/unit/test_providers.py
from unittest.mock import Mock, patch
import pytest

from hardwired.providers.base import DnsProvider
from hardwired.providers.test import TestProvider


def test_provider_implements_interface():
    provider = TestProvider(challtestsrv_url="http://localhost:8055")
    assert isinstance(provider, DnsProvider)


@patch("httpx.post")
def test_add_dns_record_calls_api(mock_post):
    mock_post.return_value = Mock(status_code=200)
    provider = TestProvider(challtestsrv_url="http://localhost:8055")

    provider.create_txt_record("example.com", "test-token-value")

    mock_post.assert_called_once()
    call_args = mock_post.call_args
    assert "/set-txt" in call_args[0][0] or call_args[1].get("url", "")
```

**Integration test (write first):**
```python
# tests/integration/test_provider.py
import pytest
from hardwired.providers.test import TestProvider


@pytest.fixture
def test_provider(challtestsrv_url):
    return TestProvider(challtestsrv_url=challtestsrv_url)


def test_create_and_delete_dns_record(test_provider):
    domain = "example.com"
    token = "test-token-abc123"

    # Should not raise
    test_provider.create_txt_record(domain, token)

    # Should not raise
    test_provider.delete_txt_record(domain, token)


def test_wait_for_propagation_immediate(test_provider):
    # For test provider, propagation is immediate
    result = test_provider.wait_for_propagation("example.com", "token", timeout=1)
    assert result is True
```

**Verify:**
- `uv run pytest tests/unit/test_providers.py -v` - all pass (mocked)
- `uv run pytest tests/integration/test_provider.py -v` - pass against running challtestsrv

---

### Step 1.5: ACME Client Core (TDD)

| Test First | Then Implement |
|------------|----------------|
| `test_fetch_directory()` | GET directory, parse to Directory model |
| `test_get_nonce()` | HEAD newNonce, extract Replay-Nonce |
| `test_signed_request_includes_nonce()` | JWS with nonce in protected header |
| `test_signed_request_updates_nonce()` | Store new nonce from response |
| `test_register_account_new()` | POST newAccount, get account URL |
| `test_register_account_existing()` | POST with onlyReturnExisting=true |
| `test_account_key_rollover()` | POST keyChange endpoint |

**Example tests (write first):**
```python
# tests/integration/test_account.py
import pytest
from hardwired import AcmeClient
from hardwired.crypto import generate_rsa_key
from hardwired.providers.test import TestProvider


@pytest.fixture
def client(pebble_directory_url, challtestsrv_url):
    return AcmeClient(
        directory_url=pebble_directory_url,
        account_key=generate_rsa_key(2048),
        dns_provider=TestProvider(challtestsrv_url),
    )


def test_fetch_directory(client):
    directory = client.directory
    assert directory.new_account is not None
    assert directory.new_order is not None
    assert directory.new_nonce is not None


def test_get_nonce(client):
    nonce = client._get_nonce()
    assert nonce is not None
    assert len(nonce) > 0


def test_register_account_new(client):
    account = client.register_account(email="test@example.com")
    assert account.status == "valid"
    assert client.account_url is not None


def test_register_account_existing(client):
    # Register once
    account1 = client.register_account(email="test@example.com")

    # Create new client with same key
    client2 = AcmeClient(
        directory_url=client.directory_url,
        account_key=client.account_key,
        dns_provider=client.dns_provider,
    )

    # Should find existing account
    account2 = client2.register_account()
    assert account2.status == "valid"
```

**Verify:** `uv run pytest tests/integration/test_account.py -v` - all pass against pebble

---

### Step 1.6: Order + Authorization Flow (TDD)

| Test First | Then Implement |
|------------|----------------|
| `test_create_order_single()` | POST newOrder for one domain |
| `test_create_order_multiple()` | POST newOrder for multiple domains |
| `test_create_order_wildcard()` | POST newOrder with wildcard |
| `test_fetch_authorizations()` | GET authorization URLs from order |
| `test_get_dns01_challenge()` | Extract dns-01 challenge from authz |
| `test_order_status_pending()` | New order status is "pending" |

**Example tests (write first):**
```python
# tests/integration/test_order.py
import pytest
from hardwired import AcmeClient
from hardwired.crypto import generate_rsa_key
from hardwired.providers.test import TestProvider


@pytest.fixture
def registered_client(pebble_directory_url, challtestsrv_url):
    client = AcmeClient(
        directory_url=pebble_directory_url,
        account_key=generate_rsa_key(2048),
        dns_provider=TestProvider(challtestsrv_url),
    )
    client.register_account(email="test@example.com")
    return client


def test_create_order_single(registered_client):
    order = registered_client.create_order(domains=["example.com"])
    assert order.status == "pending"
    assert len(order.authorizations) == 1


def test_create_order_multiple(registered_client):
    order = registered_client.create_order(domains=["example.com", "www.example.com"])
    assert order.status == "pending"
    assert len(order.authorizations) == 2


def test_create_order_wildcard(registered_client):
    order = registered_client.create_order(domains=["*.example.com"])
    assert order.status == "pending"


def test_fetch_authorizations(registered_client):
    order = registered_client.create_order(domains=["example.com"])
    authzs = registered_client.fetch_authorizations(order)
    assert len(authzs) == 1
    assert authzs[0].identifier.value == "example.com"


def test_get_dns01_challenge(registered_client):
    order = registered_client.create_order(domains=["example.com"])
    authzs = registered_client.fetch_authorizations(order)

    challenge = registered_client.get_challenge(authzs[0], challenge_type="dns-01")
    assert challenge.type == "dns-01"
    assert challenge.token is not None
```

**Verify:** `uv run pytest tests/integration/test_order.py -v` - all pass against pebble

---

### Step 1.7: DNS-01 Challenge Flow (TDD)

| Test First | Then Implement |
|------------|----------------|
| `test_compute_key_authorization()` | token + "." + thumbprint |
| `test_compute_dns_txt_value()` | base64url(sha256(keyauth)) |
| `test_respond_to_challenge()` | POST empty {} to challenge URL |
| `test_poll_challenge_valid()` | Poll until status="valid" |
| `test_poll_challenge_invalid()` | Handle status="invalid" |
| `test_complete_dns01_challenge()` | Full flow: set DNS → respond → poll |

**Example tests (write first):**
```python
# tests/unit/test_challenges.py
import base64
import hashlib
from hardwired.challenges.dns01 import compute_key_authorization, compute_dns_txt_value


def test_compute_key_authorization():
    token = "abc123"
    thumbprint = "xyz789"
    keyauth = compute_key_authorization(token, thumbprint)
    assert keyauth == "abc123.xyz789"


def test_compute_dns_txt_value():
    keyauth = "test-key-authorization"
    txt_value = compute_dns_txt_value(keyauth)

    # Should be base64url(sha256(keyauth))
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(keyauth.encode()).digest()
    ).rstrip(b"=").decode()
    assert txt_value == expected
```

```python
# tests/integration/test_challenges.py
import pytest
from hardwired import AcmeClient
from hardwired.crypto import generate_rsa_key
from hardwired.providers.test import TestProvider


@pytest.fixture
def client_with_order(pebble_directory_url, challtestsrv_url):
    client = AcmeClient(
        directory_url=pebble_directory_url,
        account_key=generate_rsa_key(2048),
        dns_provider=TestProvider(challtestsrv_url),
    )
    client.register_account(email="test@example.com")
    order = client.create_order(domains=["test.example.com"])
    return client, order


def test_complete_dns01_challenge(client_with_order):
    client, order = client_with_order
    authzs = client.fetch_authorizations(order)
    challenge = client.get_challenge(authzs[0], "dns-01")

    # Complete the challenge (sets DNS, responds, polls)
    result = client.complete_challenge(challenge, authzs[0])
    assert result.status == "valid"


def test_poll_challenge_timeout(client_with_order):
    client, order = client_with_order
    authzs = client.fetch_authorizations(order)
    challenge = client.get_challenge(authzs[0], "dns-01")

    # Don't set DNS record - should eventually fail
    # (or timeout if pebble is configured that way)
    with pytest.raises(Exception):  # ChallengeError or TimeoutError
        client.complete_challenge(challenge, authzs[0], skip_dns_setup=True)
```

**Verify:** `uv run pytest tests/integration/test_challenges.py -v` - all pass against pebble+challtestsrv

---

### Step 1.8: Certificate Issuance (TDD)

| Test First | Then Implement |
|------------|----------------|
| `test_finalize_order()` | POST CSR to finalize URL |
| `test_download_certificate()` | GET certificate URL |
| `test_full_issuance_flow()` | End-to-end: order → challenges → cert |
| `test_issuance_wildcard()` | Wildcard certificate |
| `test_issuance_san()` | Multi-domain SAN cert |
| `test_certificate_chain()` | Verify chain is complete |

**Example tests (write first):**
```python
# tests/integration/test_certificate.py
import pytest
from cryptography import x509

from hardwired import AcmeClient
from hardwired.crypto import generate_rsa_key
from hardwired.providers.test import TestProvider


@pytest.fixture
def client(pebble_directory_url, challtestsrv_url):
    client = AcmeClient(
        directory_url=pebble_directory_url,
        account_key=generate_rsa_key(2048),
        dns_provider=TestProvider(challtestsrv_url),
    )
    client.register_account(email="test@example.com")
    return client


def test_full_issuance_flow(client):
    cert_result = client.obtain_certificate(domains=["test.example.com"])

    assert cert_result.certificate_pem is not None
    assert cert_result.private_key_pem is not None
    assert cert_result.expires_at is not None

    # Parse and verify certificate
    cert = x509.load_pem_x509_certificate(cert_result.certificate_pem.encode())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    names = [name.value for name in san.value]
    assert "test.example.com" in names


def test_issuance_wildcard(client):
    cert_result = client.obtain_certificate(
        domains=["*.example.com", "example.com"]
    )

    cert = x509.load_pem_x509_certificate(cert_result.certificate_pem.encode())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    names = [name.value for name in san.value]
    assert "*.example.com" in names
    assert "example.com" in names


def test_issuance_san(client):
    domains = ["example.com", "www.example.com", "api.example.com"]
    cert_result = client.obtain_certificate(domains=domains)

    cert = x509.load_pem_x509_certificate(cert_result.certificate_pem.encode())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    names = [name.value for name in san.value]
    for domain in domains:
        assert domain in names


def test_certificate_chain(client):
    cert_result = client.obtain_certificate(domains=["test.example.com"])

    # Should contain at least 2 certs (leaf + intermediate)
    # PEM format separates certs with -----BEGIN/END CERTIFICATE-----
    cert_count = cert_result.certificate_pem.count("-----BEGIN CERTIFICATE-----")
    assert cert_count >= 1  # Pebble may return just leaf


def test_obtain_with_provided_csr(client):
    key = generate_rsa_key(2048)
    from hardwired.crypto import create_csr
    csr = create_csr(key, domains=["test.example.com"])

    cert_result = client.obtain_certificate(
        domains=["test.example.com"],
        csr=csr,
    )

    assert cert_result.certificate_pem is not None
    # Private key should be None when CSR provided externally
    assert cert_result.private_key_pem is None
```

**Verify:** `uv run pytest tests/integration/test_certificate.py -v` - all pass against pebble+challtestsrv

---

## Phase 1 Completion Checklist

- [ ] All unit tests pass: `uv run pytest tests/unit -v`
- [ ] All integration tests pass: `uv run pytest tests/integration -v`
- [ ] Coverage >80%: `uv run pytest --cov=hardwired --cov-report=term-missing`
- [ ] Type check passes: `uv run ty`
- [ ] Lint passes: `uv run ruff check`
- [ ] Format clean: `uv run ruff format --check`
- [ ] `py.typed` marker file exists
- [ ] README.md has basic usage examples

---

## Celery Integration Pattern (For Reference)

The library does NOT include Celery. Your consuming application wraps calls:

```python
# In your application (not in hardwired)
from celery import Celery
from hardwired import AcmeClient
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from your_app.providers import YourDnsProvider

app = Celery('certificates')

@app.task
def obtain_certificate(domain: str, account_key_pem: str) -> dict:
    client = AcmeClient(
        directory_url="https://acme-v02.api.letsencrypt.org/directory",
        account_key=load_pem_private_key(account_key_pem.encode(), password=None),
        dns_provider=YourDnsProvider(),
    )
    client.register_account()
    cert = client.obtain_certificate(domains=[domain])
    return {
        "certificate": cert.certificate_pem,
        "private_key": cert.private_key_pem,
        "expires_at": cert.expires_at.isoformat(),
    }
```
