"""Integration tests for certificate issuance (requires pebble + challtestsrv)."""

import pytest
from cryptography import x509

from hardwired import AcmeClient
from hardwired.crypto import create_csr, generate_rsa_key
from hardwired.providers.pebble import PebbleProvider


@pytest.fixture
def client(pebble_directory_url: str, challtestsrv_url: str, pebble_ca_cert: str) -> AcmeClient:
    """Create a registered AcmeClient configured for pebble."""
    client = AcmeClient(
        directory_url=pebble_directory_url,
        account_key=generate_rsa_key(2048),
        dns_provider=PebbleProvider(challtestsrv_url),
        ca_cert=pebble_ca_cert,
    )
    client.register_account(email="test@example.com")
    return client


class TestFullIssuanceFlow:
    """Tests for complete certificate issuance."""

    def test_full_issuance_flow(self, client: AcmeClient):
        """Should obtain certificate through complete flow."""
        cert_result = client.obtain_certificate(domains=["test.example.com"])

        assert cert_result.certificate_pem is not None
        assert cert_result.private_key_pem is not None
        assert cert_result.expires_at is not None

        # Parse and verify certificate
        cert = x509.load_pem_x509_certificate(cert_result.certificate_pem.encode())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = [name.value for name in san.value]
        assert "test.example.com" in names

    def test_issuance_wildcard(self, client: AcmeClient):
        """Should issue wildcard certificate."""
        cert_result = client.obtain_certificate(domains=["*.wild.example.com", "wild.example.com"])

        cert = x509.load_pem_x509_certificate(cert_result.certificate_pem.encode())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = [name.value for name in san.value]

        assert "*.wild.example.com" in names
        assert "wild.example.com" in names

    def test_issuance_san(self, client: AcmeClient):
        """Should issue multi-domain SAN certificate."""
        domains = ["san1.example.com", "san2.example.com", "san3.example.com"]
        cert_result = client.obtain_certificate(domains=domains)

        cert = x509.load_pem_x509_certificate(cert_result.certificate_pem.encode())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = [name.value for name in san.value]

        for domain in domains:
            assert domain in names

    def test_obtain_with_provided_csr(self, client: AcmeClient):
        """Should issue certificate with user-provided CSR."""
        # Generate key and CSR externally
        key = generate_rsa_key(2048)
        csr = create_csr(key, domains=["csr.example.com"])

        cert_result = client.obtain_certificate(
            domains=["csr.example.com"],
            csr=csr,
        )

        assert cert_result.certificate_pem is not None
        # Private key should be None when CSR provided externally
        assert cert_result.private_key_pem is None

    def test_certificate_chain(self, client: AcmeClient):
        """Certificate should include chain."""
        cert_result = client.obtain_certificate(domains=["chain.example.com"])

        # Should contain at least 1 cert (leaf)
        # Pebble may or may not include full chain
        cert_count = cert_result.certificate_pem.count("-----BEGIN CERTIFICATE-----")
        assert cert_count >= 1


class TestOrderFinalization:
    """Tests for order finalization."""

    def test_finalize_order(self, client: AcmeClient):
        """Should finalize order with CSR."""
        # Create and complete order manually
        order = client.create_order(domains=["finalize.example.com"])
        order_url = getattr(order, "_url", None)

        # Complete authorizations
        authzs = client.fetch_authorizations(order)
        for authz in authzs:
            challenge = client.get_challenge(authz, "dns-01")
            client.complete_challenge(challenge, authz)

        # Wait for order to be ready
        if order_url:
            order = client._poll_order(order_url)

        # Create and submit CSR
        key = generate_rsa_key(2048)
        csr = create_csr(key, domains=["finalize.example.com"])
        finalized_order = client.finalize_order(order, csr)

        assert finalized_order.status in ("processing", "valid")


class TestCertificateDownload:
    """Tests for certificate download."""

    def test_download_certificate(self, client: AcmeClient):
        """Should download certificate after issuance."""
        # Go through full flow
        order = client.create_order(domains=["download.example.com"])
        order_url = getattr(order, "_url", None)

        authzs = client.fetch_authorizations(order)
        for authz in authzs:
            challenge = client.get_challenge(authz, "dns-01")
            client.complete_challenge(challenge, authz)

        if order_url:
            order = client._poll_order(order_url)

        key = generate_rsa_key(2048)
        csr = create_csr(key, domains=["download.example.com"])
        order = client.finalize_order(order, csr)

        # Poll for certificate
        import time

        for _ in range(30):
            if order.certificate:
                break
            time.sleep(1)
            if order_url:
                response = client._signed_request(order_url, "")
                from hardwired.models import Order

                order = Order.model_validate(response.json())

        # Download certificate
        cert_pem = client.download_certificate(order)

        assert "-----BEGIN CERTIFICATE-----" in cert_pem
        assert "-----END CERTIFICATE-----" in cert_pem
