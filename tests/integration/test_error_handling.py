"""Integration tests for ACME error handling (requires pebble + challtestsrv)."""

import pytest

from hardwired import AcmeClient
from hardwired.crypto import create_csr, generate_rsa_key
from hardwired.exceptions import AcmeError
from hardwired.models import Identifier, Order
from hardwired.providers.pebble import PebbleProvider


@pytest.fixture
def registered_client(
    pebble_directory_url: str, challtestsrv_url: str, pebble_ca_cert: str
) -> AcmeClient:
    """Create a registered AcmeClient configured for pebble."""
    client = AcmeClient(
        directory_url=pebble_directory_url,
        account_key=generate_rsa_key(2048),
        dns_provider=PebbleProvider(challtestsrv_url),
        ca_cert=pebble_ca_cert,
    )
    client.register_account(email="test@example.com")
    return client


class TestInvalidCSRHandling:
    """Tests for invalid CSR error handling."""

    def test_csr_domain_mismatch_raises_error(self, registered_client: AcmeClient):
        """Submitting CSR with wrong domain should raise AcmeError.

        The CSR contains a domain that doesn't match the order.
        """
        # Create order for one domain
        order = registered_client.create_order(domains=["ordered-domain.example.com"])

        # Complete the authorization
        authzs = registered_client.fetch_authorizations(order)
        for authz in authzs:
            challenge = registered_client.get_challenge(authz, "dns-01")
            registered_client.complete_challenge(challenge, authz)

        # Wait for order to be ready
        order_url = getattr(order, "_url", None)
        if order_url:
            order = registered_client._poll_order(order_url)

        # Create CSR for a DIFFERENT domain
        key = generate_rsa_key(2048)
        csr = create_csr(key, domains=["wrong-domain.example.com"])

        # This should raise an error because CSR domain doesn't match order
        with pytest.raises(AcmeError) as exc_info:
            registered_client.finalize_order(order, csr)

        # The error should indicate the CSR is invalid
        assert exc_info.value.status_code >= 400

    def test_csr_missing_domain_raises_error(self, registered_client: AcmeClient):
        """CSR missing a required domain should raise AcmeError.

        Order has multiple domains but CSR only has one.
        """
        # Create order for multiple domains
        order = registered_client.create_order(domains=["multi1.example.com", "multi2.example.com"])

        # Complete all authorizations
        authzs = registered_client.fetch_authorizations(order)
        for authz in authzs:
            challenge = registered_client.get_challenge(authz, "dns-01")
            registered_client.complete_challenge(challenge, authz)

        order_url = getattr(order, "_url", None)
        if order_url:
            order = registered_client._poll_order(order_url)

        # Create CSR with only ONE of the required domains
        key = generate_rsa_key(2048)
        csr = create_csr(key, domains=["multi1.example.com"])  # Missing multi2

        # This should raise an error
        with pytest.raises(AcmeError) as exc_info:
            registered_client.finalize_order(order, csr)

        assert exc_info.value.status_code >= 400


class TestChallengeFailureHandling:
    """Tests for challenge failure error handling."""

    def test_challenge_without_dns_returns_error(
        self, pebble_directory_url: str, challtestsrv_url: str, pebble_ca_cert: str
    ):
        """Challenge validation without DNS setup should return clear error.

        The error should be an AcmeError with appropriate details.
        """
        client = AcmeClient(
            directory_url=pebble_directory_url,
            account_key=generate_rsa_key(2048),
            dns_provider=PebbleProvider(challtestsrv_url),
            ca_cert=pebble_ca_cert,
        )
        client.register_account()

        order = client.create_order(domains=["no-dns.example.com"])
        authzs = client.fetch_authorizations(order)
        challenge = client.get_challenge(authzs[0], "dns-01")

        # Skip DNS setup - should fail with clear error
        with pytest.raises(AcmeError) as exc_info:
            client.complete_challenge(challenge, authzs[0], skip_dns_setup=True)

        # Error should be unauthorized type
        assert "unauthorized" in exc_info.value.type.lower() or exc_info.value.status_code == 403


class TestOrderStateErrors:
    """Tests for order state-related errors."""

    def test_finalize_pending_order_raises_error(self, registered_client: AcmeClient):
        """Finalizing an order before challenges are complete should fail.

        Cannot submit CSR until order is "ready".
        """
        # Create order but DON'T complete challenges
        order = registered_client.create_order(domains=["pending.example.com"])

        # Try to finalize immediately (order is still "pending")
        key = generate_rsa_key(2048)
        csr = create_csr(key, domains=["pending.example.com"])

        # This should raise an error because order isn't ready
        with pytest.raises(AcmeError) as exc_info:
            registered_client.finalize_order(order, csr)

        assert exc_info.value.status_code >= 400


class TestAuthorizationErrors:
    """Tests for authorization-related errors."""

    def test_fetch_invalid_authorization_raises_error(self, registered_client: AcmeClient):
        """Fetching a non-existent authorization should raise an error."""
        # Create a fake order with an invalid authorization URL
        fake_order = Order(
            status="pending",
            identifiers=[Identifier(type="dns", value="fake.example.com")],
            authorizations=["https://localhost:14000/authz/nonexistent-id"],
            finalize="https://localhost:14000/finalize/nonexistent",
        )

        with pytest.raises(AcmeError) as exc_info:
            registered_client.fetch_authorizations(fake_order)

        assert exc_info.value.status_code >= 400
