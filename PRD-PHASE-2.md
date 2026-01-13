# PRD Phase 2: HTTP-01 Challenge Support

## Overview

This phase adds HTTP-01 challenge support to the Hardwired ACME client library, complementing the DNS-01 support from Phase 1.

**Prerequisites:** Phase 1 must be complete with all tests passing.

---

## Phase 2 Goals

- HTTP-01 challenge implementation
- Pluggable HTTP provider architecture
- Test provider for pebble-challtestsrv HTTP-01
- Challenge type selection (dns-01, http-01, or auto)
- Maintain >80% test coverage

## Non-Goals (This Phase)

- RFC 9773 renewal information (Phase 3)
- Production HTTP providers (nginx, Apache, etc.)

---

## Development Methodology: Test-Driven Development

**Every feature follows this cycle:**
1. **Write tests first** - Define expected behavior via failing tests
2. **Run tests** - Confirm they fail (red)
3. **Implement code** - Write minimal code to pass tests
4. **Run tests** - Confirm they pass (green)
5. **Refactor** - Clean up while tests stay green

**Completion criteria**: Phase 2 is NOT complete until all HTTP-01 tests pass against pebble + pebble-challtestsrv.

---

## Architecture Changes

### New Files

```
src/hardwired/
├── challenges/
│   └── http01.py         # HTTP-01 implementation (NEW)
└── providers/
    └── http_test.py      # HTTP test provider for challtestsrv (NEW)
```

### HTTP Provider Interface

```python
from abc import ABC, abstractmethod

class HttpProvider(ABC):
    @abstractmethod
    def create_challenge_response(self, token: str, key_authorization: str) -> None:
        """
        Make key_authorization available at:
        http://{domain}/.well-known/acme-challenge/{token}
        """
        ...

    @abstractmethod
    def delete_challenge_response(self, token: str) -> None:
        """Remove the challenge response."""
        ...
```

### Updated Client API

```python
from hardwired import AcmeClient
from hardwired.providers.test import TestDnsProvider
from hardwired.providers.http_test import TestHttpProvider

# With HTTP-01 only
client = AcmeClient(
    directory_url="https://acme-v02.api.letsencrypt.org/directory",
    account_key=account_key,
    http_provider=TestHttpProvider(),
)

# With both providers (client chooses based on availability)
client = AcmeClient(
    directory_url="https://acme-v02.api.letsencrypt.org/directory",
    account_key=account_key,
    dns_provider=TestDnsProvider(),
    http_provider=TestHttpProvider(),
    preferred_challenge="http-01",  # or "dns-01" or "auto"
)

# Request certificate (uses http-01 if available for non-wildcard)
cert = client.obtain_certificate(domains=["example.com"])

# Wildcards still require DNS-01
cert = client.obtain_certificate(domains=["*.example.com"])  # Uses dns-01
```

---

## Implementation Steps (TDD)

### Step 2.1: HTTP Provider Interface (TDD)

| Test First | Then Implement |
|------------|----------------|
| `test_http_provider_abc()` | `HttpProvider` abstract base class |
| `test_http_provider_methods()` | Required method signatures |

**Example test (write first):**
```python
# tests/unit/test_http_provider.py
import pytest
from abc import ABC
from hardwired.providers.http_base import HttpProvider


def test_http_provider_is_abc():
    assert issubclass(HttpProvider, ABC)


def test_http_provider_has_required_methods():
    # Should have create_challenge_response and delete_challenge_response
    assert hasattr(HttpProvider, "create_challenge_response")
    assert hasattr(HttpProvider, "delete_challenge_response")


def test_cannot_instantiate_http_provider():
    with pytest.raises(TypeError):
        HttpProvider()
```

**Verify:** `uv run pytest tests/unit/test_http_provider.py -v` - all pass

---

### Step 2.2: Test HTTP Provider for pebble-challtestsrv (TDD)

| Test First | Then Implement |
|------------|----------------|
| `test_http_test_provider_implements_interface()` | TestHttpProvider class |
| `test_add_http_challenge()` | POST to challtestsrv /add-http01 |
| `test_delete_http_challenge()` | POST to challtestsrv /del-http01 |

**pebble-challtestsrv HTTP-01 API:**
```
POST /add-http01
{
  "token": "challenge-token",
  "content": "key-authorization-string"
}

POST /del-http01
{
  "token": "challenge-token"
}
```

**Example test (write first):**
```python
# tests/unit/test_http_test_provider.py
from unittest.mock import Mock, patch
import pytest

from hardwired.providers.http_base import HttpProvider
from hardwired.providers.http_test import TestHttpProvider


def test_http_test_provider_implements_interface():
    provider = TestHttpProvider(challtestsrv_url="http://localhost:8055")
    assert isinstance(provider, HttpProvider)


@patch("httpx.post")
def test_add_http_challenge_calls_api(mock_post):
    mock_post.return_value = Mock(status_code=200)
    provider = TestHttpProvider(challtestsrv_url="http://localhost:8055")

    provider.create_challenge_response("test-token", "key-auth-value")

    mock_post.assert_called_once()
    call_url = mock_post.call_args[0][0]
    assert "add-http01" in call_url


@patch("httpx.post")
def test_delete_http_challenge_calls_api(mock_post):
    mock_post.return_value = Mock(status_code=200)
    provider = TestHttpProvider(challtestsrv_url="http://localhost:8055")

    provider.delete_challenge_response("test-token")

    mock_post.assert_called_once()
    call_url = mock_post.call_args[0][0]
    assert "del-http01" in call_url
```

**Integration test (write first):**
```python
# tests/integration/test_http_provider.py
import pytest
from hardwired.providers.http_test import TestHttpProvider


@pytest.fixture
def http_provider(challtestsrv_url):
    return TestHttpProvider(challtestsrv_url=challtestsrv_url)


def test_create_and_delete_http_challenge(http_provider):
    token = "test-http-token-abc123"
    key_auth = "test-key-authorization"

    # Should not raise
    http_provider.create_challenge_response(token, key_auth)

    # Should not raise
    http_provider.delete_challenge_response(token)
```

**Verify:**
- `uv run pytest tests/unit/test_http_test_provider.py -v` - all pass (mocked)
- `uv run pytest tests/integration/test_http_provider.py -v` - pass against challtestsrv

---

### Step 2.3: HTTP-01 Challenge Handler (TDD)

| Test First | Then Implement |
|------------|----------------|
| `test_http01_token_path()` | Compute `.well-known/acme-challenge/{token}` |
| `test_http01_response_content()` | Key authorization as plain text |
| `test_http01_challenge_type()` | `challenge.type == "http-01"` |

**Example test (write first):**
```python
# tests/unit/test_http01_challenge.py
from hardwired.challenges.http01 import (
    get_challenge_path,
    get_challenge_response,
)


def test_http01_token_path():
    token = "abc123xyz"
    path = get_challenge_path(token)
    assert path == "/.well-known/acme-challenge/abc123xyz"


def test_http01_response_content():
    token = "abc123"
    thumbprint = "xyz789"
    response = get_challenge_response(token, thumbprint)
    # HTTP-01 response is the key authorization itself (not hashed like DNS-01)
    assert response == "abc123.xyz789"


def test_http01_response_is_plain_text():
    # Response should be plain text, not base64 encoded
    token = "abc123"
    thumbprint = "xyz789"
    response = get_challenge_response(token, thumbprint)
    assert "." in response
    assert response == f"{token}.{thumbprint}"
```

**Verify:** `uv run pytest tests/unit/test_http01_challenge.py -v` - all pass

---

### Step 2.4: Client HTTP-01 Integration (TDD)

| Test First | Then Implement |
|------------|----------------|
| `test_client_accepts_http_provider()` | Constructor with http_provider |
| `test_get_http01_challenge()` | Extract http-01 from authorization |
| `test_complete_http01_challenge()` | Full http-01 flow |
| `test_http01_issuance()` | Certificate via HTTP-01 |

**Example tests (write first):**
```python
# tests/integration/test_http01.py
import pytest
from cryptography import x509

from hardwired import AcmeClient
from hardwired.crypto import generate_rsa_key
from hardwired.providers.http_test import TestHttpProvider


@pytest.fixture
def http_client(pebble_directory_url, challtestsrv_url):
    client = AcmeClient(
        directory_url=pebble_directory_url,
        account_key=generate_rsa_key(2048),
        http_provider=TestHttpProvider(challtestsrv_url),
    )
    client.register_account(email="test@example.com")
    return client


def test_get_http01_challenge(http_client):
    order = http_client.create_order(domains=["example.com"])
    authzs = http_client.fetch_authorizations(order)

    challenge = http_client.get_challenge(authzs[0], challenge_type="http-01")
    assert challenge.type == "http-01"
    assert challenge.token is not None


def test_complete_http01_challenge(http_client):
    order = http_client.create_order(domains=["example.com"])
    authzs = http_client.fetch_authorizations(order)
    challenge = http_client.get_challenge(authzs[0], "http-01")

    result = http_client.complete_challenge(challenge, authzs[0])
    assert result.status == "valid"


def test_http01_issuance(http_client):
    cert_result = http_client.obtain_certificate(domains=["test.example.com"])

    assert cert_result.certificate_pem is not None

    cert = x509.load_pem_x509_certificate(cert_result.certificate_pem.encode())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    names = [name.value for name in san.value]
    assert "test.example.com" in names


def test_http01_multi_domain(http_client):
    domains = ["example.com", "www.example.com"]
    cert_result = http_client.obtain_certificate(domains=domains)

    cert = x509.load_pem_x509_certificate(cert_result.certificate_pem.encode())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    names = [name.value for name in san.value]
    for domain in domains:
        assert domain in names
```

**Verify:** `uv run pytest tests/integration/test_http01.py -v` - all pass against pebble+challtestsrv

---

### Step 2.5: Challenge Type Selection (TDD)

| Test First | Then Implement |
|------------|----------------|
| `test_wildcard_requires_dns01()` | Wildcard domains use dns-01 |
| `test_preferred_challenge_dns()` | Respect preferred_challenge="dns-01" |
| `test_preferred_challenge_http()` | Respect preferred_challenge="http-01" |
| `test_auto_selects_available()` | "auto" picks based on providers |
| `test_fallback_on_missing_provider()` | Error if required provider missing |

**Example tests (write first):**
```python
# tests/unit/test_challenge_selection.py
import pytest
from hardwired.client import select_challenge_type
from hardwired.models import Authorization, Challenge


def create_authz_with_challenges(domain: str, challenge_types: list[str]) -> Authorization:
    """Helper to create mock authorization with specified challenge types."""
    challenges = [
        Challenge(type=ctype, url=f"https://example.com/{ctype}", status="pending", token="abc")
        for ctype in challenge_types
    ]
    return Authorization(
        identifier={"type": "dns", "value": domain},
        status="pending",
        challenges=challenges,
    )


def test_wildcard_requires_dns01():
    authz = create_authz_with_challenges("*.example.com", ["dns-01", "http-01"])

    selected = select_challenge_type(
        authz,
        preferred="auto",
        has_dns_provider=True,
        has_http_provider=True,
    )
    assert selected == "dns-01"


def test_wildcard_without_dns_provider_raises():
    authz = create_authz_with_challenges("*.example.com", ["dns-01"])

    with pytest.raises(ValueError, match="dns.*wildcard"):
        select_challenge_type(
            authz,
            preferred="auto",
            has_dns_provider=False,
            has_http_provider=True,
        )


def test_preferred_challenge_respected():
    authz = create_authz_with_challenges("example.com", ["dns-01", "http-01"])

    selected = select_challenge_type(
        authz,
        preferred="http-01",
        has_dns_provider=True,
        has_http_provider=True,
    )
    assert selected == "http-01"


def test_auto_prefers_http_for_non_wildcard():
    """When both available, auto might prefer http-01 (faster validation)."""
    authz = create_authz_with_challenges("example.com", ["dns-01", "http-01"])

    selected = select_challenge_type(
        authz,
        preferred="auto",
        has_dns_provider=True,
        has_http_provider=True,
    )
    # Either is acceptable for auto, but should pick one consistently
    assert selected in ["dns-01", "http-01"]


def test_missing_preferred_provider_raises():
    authz = create_authz_with_challenges("example.com", ["dns-01", "http-01"])

    with pytest.raises(ValueError, match="http.*provider"):
        select_challenge_type(
            authz,
            preferred="http-01",
            has_dns_provider=True,
            has_http_provider=False,
        )
```

**Integration test:**
```python
# tests/integration/test_challenge_selection.py
import pytest
from hardwired import AcmeClient
from hardwired.crypto import generate_rsa_key
from hardwired.providers.test import TestDnsProvider
from hardwired.providers.http_test import TestHttpProvider


@pytest.fixture
def dual_client(pebble_directory_url, challtestsrv_url):
    """Client with both DNS and HTTP providers."""
    client = AcmeClient(
        directory_url=pebble_directory_url,
        account_key=generate_rsa_key(2048),
        dns_provider=TestDnsProvider(challtestsrv_url),
        http_provider=TestHttpProvider(challtestsrv_url),
    )
    client.register_account(email="test@example.com")
    return client


def test_wildcard_uses_dns01(dual_client):
    # Wildcards can only use DNS-01
    cert = dual_client.obtain_certificate(
        domains=["*.example.com"],
        preferred_challenge="auto",
    )
    assert cert.certificate_pem is not None


def test_explicit_http01_preference(dual_client):
    cert = dual_client.obtain_certificate(
        domains=["example.com"],
        preferred_challenge="http-01",
    )
    assert cert.certificate_pem is not None


def test_explicit_dns01_preference(dual_client):
    cert = dual_client.obtain_certificate(
        domains=["example.com"],
        preferred_challenge="dns-01",
    )
    assert cert.certificate_pem is not None
```

**Verify:** `uv run pytest tests/integration/test_challenge_selection.py -v` - all pass

---

## Updated docker-compose.test.yml

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
      - "14000:14000"
      - "15000:15000"
    networks:
      - acme-test
    depends_on:
      - challtestsrv

  challtestsrv:
    image: letsencrypt/pebble-challtestsrv
    command: >
      pebble-challtestsrv
      -defaultIPv4 10.30.50.1
      -dns01 ":8053"
      -http01 ":5002"
      -https01 ""
      -tlsalpn01 ""
    ports:
      - "8055:8055"   # Management API
      - "5002:5002"   # HTTP-01 challenge server
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

## Phase 2 Completion Checklist

- [ ] HTTP provider interface implemented
- [ ] TestHttpProvider works with pebble-challtestsrv
- [ ] HTTP-01 challenge handler complete
- [ ] Challenge type selection logic works
- [ ] All unit tests pass: `uv run pytest tests/unit -v`
- [ ] All integration tests pass: `uv run pytest tests/integration -v`
- [ ] Coverage >80%: `uv run pytest --cov=hardwired --cov-report=term-missing`
- [ ] Type check passes: `uv run ty`
- [ ] Lint passes: `uv run ruff check`
- [ ] Format clean: `uv run ruff format --check`
