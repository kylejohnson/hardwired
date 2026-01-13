# PRD Phase 3: RFC 9773 Renewal Information

## Overview

This phase adds RFC 9773 (ACME Renewal Information) support to the Hardwired ACME client library. This extension allows ACME servers to suggest optimal certificate renewal windows.

**Prerequisites:** Phase 1 and Phase 2 must be complete with all tests passing.

---

## Phase 3 Goals

- Full RFC 9773 compliance
- RenewalInfo resource fetching and parsing
- `should_renew()` helper method for renewal decisions
- Order "replaces" field for certificate replacement tracking
- Maintain >80% test coverage

## Non-Goals (This Phase)

- Automatic renewal scheduling (caller's responsibility)
- Background renewal monitoring

---

## Development Methodology: Test-Driven Development

**Every feature follows this cycle:**
1. **Write tests first** - Define expected behavior via failing tests
2. **Run tests** - Confirm they fail (red)
3. **Implement code** - Write minimal code to pass tests
4. **Run tests** - Confirm they pass (green)
5. **Refactor** - Clean up while tests stay green

**Completion criteria**: Phase 3 is NOT complete until all renewal info tests pass.

**Note**: Pebble may not support RFC 9773. Tests may need to mock server responses or use a stub server.

---

## RFC 9773 Summary

### RenewalInfo Resource

The server exposes a `renewalInfo` endpoint in the directory. Clients can GET this endpoint with a certificate identifier to receive suggested renewal timing.

**Request:**
```
GET /acme/renewal-info/{certID}
```

**Response:**
```json
{
  "suggestedWindow": {
    "start": "2024-06-01T00:00:00Z",
    "end": "2024-06-15T00:00:00Z"
  },
  "explanationURL": "https://example.com/docs/renewal-policy"
}
```

### Order "replaces" Field

When renewing a certificate, the order can include a `replaces` field referencing the certificate being replaced:

```json
{
  "identifiers": [{"type": "dns", "value": "example.com"}],
  "replaces": "aGVsbG8"
}
```

The `replaces` value is the ARI certificate ID (base64url of the certificate's AuthorityKeyIdentifier + Serial Number).

---

## Architecture Changes

### New Files

```
src/hardwired/
├── renewal.py            # RFC 9773 renewal info (NEW)
└── models.py             # Add RenewalInfo, SuggestedWindow models
```

### Updated Models

```python
# In models.py
from datetime import datetime
from pydantic import BaseModel

class SuggestedWindow(BaseModel):
    start: datetime
    end: datetime

class RenewalInfo(BaseModel):
    suggested_window: SuggestedWindow
    explanation_url: str | None = None

    def should_renew_now(self) -> bool:
        """Returns True if current time is within the suggested window."""
        now = datetime.now(timezone.utc)
        return self.suggested_window.start <= now <= self.suggested_window.end

    def should_renew_soon(self, buffer_days: int = 7) -> bool:
        """Returns True if within buffer_days of the renewal window start."""
        now = datetime.now(timezone.utc)
        buffer_start = self.suggested_window.start - timedelta(days=buffer_days)
        return now >= buffer_start
```

### Updated Client API

```python
from hardwired import AcmeClient
from hardwired.renewal import compute_ari_cert_id

# Check if certificate should be renewed
client = AcmeClient(...)

# Get renewal info for an existing certificate
cert_pem = "-----BEGIN CERTIFICATE-----..."
renewal_info = client.get_renewal_info(cert_pem)

if renewal_info.should_renew_now():
    print("Certificate should be renewed now")
elif renewal_info.should_renew_soon(buffer_days=7):
    print("Certificate renewal window approaching")

# Renew with "replaces" field
new_cert = client.obtain_certificate(
    domains=["example.com"],
    replaces=cert_pem,  # Previous certificate being replaced
)
```

---

## Implementation Steps (TDD)

### Step 3.1: ARI Certificate ID Computation (TDD)

| Test First | Then Implement |
|------------|----------------|
| `test_compute_ari_cert_id()` | base64url(AKI + SerialNumber) |
| `test_ari_cert_id_format()` | Verify URL-safe base64 encoding |
| `test_ari_cert_id_from_pem()` | Extract from PEM certificate |

**Example tests (write first):**
```python
# tests/unit/test_renewal.py
import base64
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from hardwired.renewal import compute_ari_cert_id


def test_compute_ari_cert_id_format():
    # Create a test certificate or use a fixture
    cert_pem = """-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpegXFqzMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnBl
YmJsZTAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBQxEjAQBgNVBAMM
CWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABL...
-----END CERTIFICATE-----"""

    cert_id = compute_ari_cert_id(cert_pem)

    # Should be base64url encoded (no padding, URL-safe chars)
    assert "+" not in cert_id
    assert "/" not in cert_id
    assert "=" not in cert_id
    assert len(cert_id) > 0


def test_compute_ari_cert_id_components():
    """
    ARI cert ID = base64url(AKI || SerialNumber)
    where AKI is the Authority Key Identifier
    and SerialNumber is the certificate's serial number in DER format.
    """
    # Use a known certificate with known AKI and serial
    # This test verifies the computation is correct
    pass  # Implement with actual test certificate


def test_compute_ari_cert_id_deterministic():
    cert_pem = "..."  # Test certificate
    id1 = compute_ari_cert_id(cert_pem)
    id2 = compute_ari_cert_id(cert_pem)
    assert id1 == id2
```

**Verify:** `uv run pytest tests/unit/test_renewal.py -v` - all pass

---

### Step 3.2: RenewalInfo Models (TDD)

| Test First | Then Implement |
|------------|----------------|
| `test_suggested_window_model()` | Parse start/end timestamps |
| `test_renewal_info_model()` | Parse full response |
| `test_should_renew_now_true()` | Within window returns True |
| `test_should_renew_now_false()` | Before window returns False |
| `test_should_renew_soon()` | Buffer period logic |

**Example tests (write first):**
```python
# tests/unit/test_renewal_models.py
from datetime import datetime, timedelta, timezone
import pytest

from hardwired.models import RenewalInfo, SuggestedWindow


def test_suggested_window_model():
    data = {
        "start": "2024-06-01T00:00:00Z",
        "end": "2024-06-15T00:00:00Z",
    }
    window = SuggestedWindow.model_validate(data)
    assert window.start.year == 2024
    assert window.start.month == 6
    assert window.end.day == 15


def test_renewal_info_model():
    data = {
        "suggestedWindow": {
            "start": "2024-06-01T00:00:00Z",
            "end": "2024-06-15T00:00:00Z",
        },
        "explanationURL": "https://example.com/renewal-policy",
    }
    info = RenewalInfo.model_validate(data)
    assert info.suggested_window is not None
    assert info.explanation_url == "https://example.com/renewal-policy"


def test_renewal_info_without_explanation_url():
    data = {
        "suggestedWindow": {
            "start": "2024-06-01T00:00:00Z",
            "end": "2024-06-15T00:00:00Z",
        },
    }
    info = RenewalInfo.model_validate(data)
    assert info.explanation_url is None


def test_should_renew_now_within_window():
    now = datetime.now(timezone.utc)
    info = RenewalInfo(
        suggested_window=SuggestedWindow(
            start=now - timedelta(days=1),
            end=now + timedelta(days=7),
        )
    )
    assert info.should_renew_now() is True


def test_should_renew_now_before_window():
    now = datetime.now(timezone.utc)
    info = RenewalInfo(
        suggested_window=SuggestedWindow(
            start=now + timedelta(days=7),
            end=now + timedelta(days=14),
        )
    )
    assert info.should_renew_now() is False


def test_should_renew_now_after_window():
    now = datetime.now(timezone.utc)
    info = RenewalInfo(
        suggested_window=SuggestedWindow(
            start=now - timedelta(days=14),
            end=now - timedelta(days=7),
        )
    )
    # After window - should probably still renew (expired window)
    assert info.should_renew_now() is False  # Strictly speaking, outside window


def test_should_renew_soon_within_buffer():
    now = datetime.now(timezone.utc)
    info = RenewalInfo(
        suggested_window=SuggestedWindow(
            start=now + timedelta(days=5),  # 5 days away
            end=now + timedelta(days=12),
        )
    )
    assert info.should_renew_soon(buffer_days=7) is True  # Within 7-day buffer
    assert info.should_renew_soon(buffer_days=3) is False  # Outside 3-day buffer


def test_should_renew_soon_already_in_window():
    now = datetime.now(timezone.utc)
    info = RenewalInfo(
        suggested_window=SuggestedWindow(
            start=now - timedelta(days=1),
            end=now + timedelta(days=7),
        )
    )
    # Already in window, should definitely return True
    assert info.should_renew_soon(buffer_days=7) is True
```

**Verify:** `uv run pytest tests/unit/test_renewal_models.py -v` - all pass

---

### Step 3.3: Client get_renewal_info() (TDD)

| Test First | Then Implement |
|------------|----------------|
| `test_get_renewal_info_url()` | Construct correct endpoint URL |
| `test_get_renewal_info_request()` | GET request (not POST-as-GET) |
| `test_get_renewal_info_parses_response()` | Parse RenewalInfo from JSON |
| `test_get_renewal_info_not_supported()` | Handle missing renewalInfo in directory |

**Example tests (write first):**
```python
# tests/unit/test_client_renewal.py
from unittest.mock import Mock, patch
import pytest

from hardwired import AcmeClient
from hardwired.crypto import generate_rsa_key


def test_get_renewal_info_url_construction():
    """Renewal info URL should be directory.renewalInfo + '/' + certID"""
    # This is a unit test with mocked responses
    pass


def test_get_renewal_info_uses_get_not_post():
    """RFC 9773 specifies GET requests for renewalInfo (not POST-as-GET)"""
    pass


def test_get_renewal_info_not_supported():
    """Should raise appropriate error if server doesn't support RFC 9773"""
    pass
```

**Integration test (may need mocking if pebble doesn't support RFC 9773):**
```python
# tests/integration/test_renewal.py
import pytest
from hardwired import AcmeClient
from hardwired.crypto import generate_rsa_key
from hardwired.providers.test import TestDnsProvider
from hardwired.exceptions import RenewalInfoNotSupported


@pytest.fixture
def client_with_cert(pebble_directory_url, challtestsrv_url):
    """Client that has issued a certificate."""
    client = AcmeClient(
        directory_url=pebble_directory_url,
        account_key=generate_rsa_key(2048),
        dns_provider=TestDnsProvider(challtestsrv_url),
    )
    client.register_account(email="test@example.com")

    cert_result = client.obtain_certificate(domains=["example.com"])
    return client, cert_result


def test_get_renewal_info(client_with_cert):
    client, cert_result = client_with_cert

    try:
        renewal_info = client.get_renewal_info(cert_result.certificate_pem)
        assert renewal_info.suggested_window is not None
    except RenewalInfoNotSupported:
        pytest.skip("Server does not support RFC 9773 renewalInfo")


def test_renewal_info_for_unknown_cert(client_with_cert):
    client, _ = client_with_cert

    # Use a certificate the server doesn't know about
    unknown_cert_pem = "..."  # Some other certificate

    try:
        with pytest.raises(Exception):  # Appropriate error type
            client.get_renewal_info(unknown_cert_pem)
    except RenewalInfoNotSupported:
        pytest.skip("Server does not support RFC 9773 renewalInfo")
```

**Verify:** `uv run pytest tests/integration/test_renewal.py -v`

---

### Step 3.4: Order "replaces" Field (TDD)

| Test First | Then Implement |
|------------|----------------|
| `test_order_with_replaces()` | Include replaces in order payload |
| `test_replaces_is_ari_cert_id()` | Correct format for replaces value |
| `test_renewal_issuance()` | Full flow with replaces |

**Example tests (write first):**
```python
# tests/unit/test_order_replaces.py
from unittest.mock import Mock, patch
import pytest

from hardwired import AcmeClient
from hardwired.crypto import generate_rsa_key
from hardwired.renewal import compute_ari_cert_id


def test_create_order_includes_replaces():
    """When replaces is provided, order payload should include it."""
    pass


def test_replaces_value_is_ari_cert_id():
    """The replaces value should be the ARI certificate ID."""
    old_cert_pem = "..."
    expected_id = compute_ari_cert_id(old_cert_pem)

    # Verify the order payload contains this ID
    pass
```

**Integration test:**
```python
# tests/integration/test_renewal_order.py
import pytest
from cryptography import x509

from hardwired import AcmeClient
from hardwired.crypto import generate_rsa_key
from hardwired.providers.test import TestDnsProvider


@pytest.fixture
def client(pebble_directory_url, challtestsrv_url):
    client = AcmeClient(
        directory_url=pebble_directory_url,
        account_key=generate_rsa_key(2048),
        dns_provider=TestDnsProvider(challtestsrv_url),
    )
    client.register_account(email="test@example.com")
    return client


def test_renewal_with_replaces(client):
    # Issue initial certificate
    initial_cert = client.obtain_certificate(domains=["example.com"])

    # Renew with replaces field
    renewed_cert = client.obtain_certificate(
        domains=["example.com"],
        replaces=initial_cert.certificate_pem,
    )

    assert renewed_cert.certificate_pem is not None
    assert renewed_cert.certificate_pem != initial_cert.certificate_pem

    # Verify new certificate is valid
    cert = x509.load_pem_x509_certificate(renewed_cert.certificate_pem.encode())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    names = [name.value for name in san.value]
    assert "example.com" in names


def test_renewal_with_additional_domains(client):
    # Issue initial certificate for one domain
    initial_cert = client.obtain_certificate(domains=["example.com"])

    # Renew with additional domains
    renewed_cert = client.obtain_certificate(
        domains=["example.com", "www.example.com"],
        replaces=initial_cert.certificate_pem,
    )

    cert = x509.load_pem_x509_certificate(renewed_cert.certificate_pem.encode())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    names = [name.value for name in san.value]
    assert "example.com" in names
    assert "www.example.com" in names
```

**Verify:** `uv run pytest tests/integration/test_renewal_order.py -v`

---

## Handling Pebble Limitations

Pebble may not support RFC 9773. Options for testing:

### Option 1: Skip Tests When Unsupported
```python
def test_renewal_info(client):
    if "renewalInfo" not in client.directory.model_dump():
        pytest.skip("Server does not support RFC 9773")
    # ... rest of test
```

### Option 2: Mock Server Responses
```python
@pytest.fixture
def mock_renewal_info_response():
    return {
        "suggestedWindow": {
            "start": "2024-06-01T00:00:00Z",
            "end": "2024-06-15T00:00:00Z",
        }
    }


def test_parse_renewal_info(mock_renewal_info_response):
    info = RenewalInfo.model_validate(mock_renewal_info_response)
    assert info.should_renew_soon(buffer_days=30) is True
```

### Option 3: Stub Server
Create a simple HTTP server that implements the renewalInfo endpoint for testing.

---

## Updated Client Interface

```python
class AcmeClient:
    def __init__(
        self,
        directory_url: str,
        account_key: PrivateKey,
        dns_provider: DnsProvider | None = None,
        http_provider: HttpProvider | None = None,
        preferred_challenge: str = "auto",  # "dns-01", "http-01", "auto"
    ): ...

    def register_account(self, email: str | None = None) -> Account: ...

    def create_order(
        self,
        domains: list[str],
        replaces: str | None = None,  # NEW: PEM certificate being replaced
    ) -> Order: ...

    def obtain_certificate(
        self,
        domains: list[str],
        csr: CSR | None = None,
        preferred_challenge: str | None = None,
        replaces: str | None = None,  # NEW: PEM certificate being replaced
    ) -> CertificateResult: ...

    def get_renewal_info(self, certificate_pem: str) -> RenewalInfo:  # NEW
        """
        Get renewal information for an existing certificate.

        Args:
            certificate_pem: PEM-encoded certificate

        Returns:
            RenewalInfo with suggested renewal window

        Raises:
            RenewalInfoNotSupported: Server doesn't support RFC 9773
        """
        ...
```

---

## Phase 3 Completion Checklist

- [ ] ARI certificate ID computation implemented
- [ ] RenewalInfo and SuggestedWindow models complete
- [ ] should_renew_now() and should_renew_soon() methods work
- [ ] get_renewal_info() client method implemented
- [ ] Order "replaces" field supported
- [ ] Graceful handling when server doesn't support RFC 9773
- [ ] All unit tests pass: `uv run pytest tests/unit -v`
- [ ] All integration tests pass: `uv run pytest tests/integration -v`
- [ ] Coverage >80%: `uv run pytest --cov=hardwired --cov-report=term-missing`
- [ ] Type check passes: `uv run ty`
- [ ] Lint passes: `uv run ruff check`
- [ ] Format clean: `uv run ruff format --check`

---

## Usage Examples

### Basic Renewal Check

```python
from hardwired import AcmeClient
from hardwired.providers.your_dns import YourDnsProvider

client = AcmeClient(
    directory_url="https://acme-v02.api.letsencrypt.org/directory",
    account_key=load_account_key(),
    dns_provider=YourDnsProvider(),
)
client.register_account()

# Load existing certificate
with open("cert.pem") as f:
    cert_pem = f.read()

# Check if renewal is needed
try:
    renewal_info = client.get_renewal_info(cert_pem)

    if renewal_info.should_renew_now():
        new_cert = client.obtain_certificate(
            domains=["example.com"],
            replaces=cert_pem,
        )
        save_certificate(new_cert)
    elif renewal_info.should_renew_soon(buffer_days=7):
        schedule_renewal()
except RenewalInfoNotSupported:
    # Fall back to expiration-based renewal
    check_certificate_expiration(cert_pem)
```

### Celery Task with Renewal Info

```python
# In your application
from celery import Celery
from hardwired import AcmeClient
from hardwired.exceptions import RenewalInfoNotSupported

app = Celery('certificates')

@app.task
def check_and_renew(domain: str, current_cert_pem: str) -> dict | None:
    client = AcmeClient(...)
    client.register_account()

    try:
        renewal_info = client.get_renewal_info(current_cert_pem)

        if not renewal_info.should_renew_soon(buffer_days=14):
            return None  # No renewal needed

    except RenewalInfoNotSupported:
        # Check expiration manually
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(current_cert_pem.encode())
        days_until_expiry = (cert.not_valid_after_utc - datetime.now(timezone.utc)).days
        if days_until_expiry > 30:
            return None

    # Renew
    new_cert = client.obtain_certificate(
        domains=[domain],
        replaces=current_cert_pem,
    )

    return {
        "certificate": new_cert.certificate_pem,
        "private_key": new_cert.private_key_pem,
        "expires_at": new_cert.expires_at.isoformat(),
    }
```
