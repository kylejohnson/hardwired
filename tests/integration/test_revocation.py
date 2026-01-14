"""Integration tests for certificate revocation (requires pebble + challtestsrv)."""

import pytest

from hardwired import AcmeClient
from hardwired.crypto import generate_rsa_key
from hardwired.exceptions import AcmeError
from hardwired.providers.test import TestProvider


@pytest.fixture
def client(pebble_directory_url: str, challtestsrv_url: str, pebble_ca_cert: str) -> AcmeClient:
    """Create a registered AcmeClient configured for pebble."""
    client = AcmeClient(
        directory_url=pebble_directory_url,
        account_key=generate_rsa_key(2048),
        dns_provider=TestProvider(challtestsrv_url),
        ca_cert=pebble_ca_cert,
    )
    client.register_account(email="test@example.com")
    return client


class TestCertificateRevocation:
    """Tests for certificate revocation (RFC 8555 Section 7.6)."""

    def test_revoke_certificate(self, client: AcmeClient):
        """Should revoke a valid certificate."""
        # Issue a certificate
        result = client.obtain_certificate(
            domains=["revoke-test.example.com", "*.revoke-test.example.com"]
        )

        # Revoke it - should not raise
        client.revoke_certificate(result.certificate_pem)

    def test_revoke_certificate_with_reason(self, client: AcmeClient):
        """Should revoke certificate with cessationOfOperation reason code."""
        result = client.obtain_certificate(
            domains=["revoke-reason.example.com", "*.revoke-reason.example.com"]
        )

        # Revoke with reason=5 (cessationOfOperation)
        client.revoke_certificate(result.certificate_pem, reason=5)

    def test_revoke_certificate_key_compromise(self, client: AcmeClient):
        """Should revoke certificate with keyCompromise reason code."""
        result = client.obtain_certificate(
            domains=["revoke-keycomp.example.com", "*.revoke-keycomp.example.com"]
        )

        # Revoke with reason=1 (keyCompromise)
        client.revoke_certificate(result.certificate_pem, reason=1)

    def test_revoke_invalid_certificate_raises_error(self, client: AcmeClient):
        """Revoking an invalid certificate should raise AcmeError."""
        invalid_cert = """-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKbX9234567890MA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMM
BnVudXNlZDAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBExDzANBgNV
BAMMBnVudXNlZDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7o96tr5mR9JEOmn9K
aFJ7dHZBe/example/invalid/base64/content/hereABCDEF123456789==
-----END CERTIFICATE-----"""

        with pytest.raises(AcmeError):
            client.revoke_certificate(invalid_cert)

    def test_revoke_certificate_twice_raises_error(self, client: AcmeClient):
        """Revoking an already revoked certificate should raise AcmeError."""
        result = client.obtain_certificate(
            domains=["revoke-twice.example.com", "*.revoke-twice.example.com"]
        )

        # First revocation should succeed
        client.revoke_certificate(result.certificate_pem)

        # Second revocation should fail
        with pytest.raises(AcmeError):
            client.revoke_certificate(result.certificate_pem)
