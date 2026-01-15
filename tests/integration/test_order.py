"""Integration tests for ACME order operations (requires pebble)."""

import pytest

from hardwired import AcmeClient
from hardwired.crypto import generate_rsa_key
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


class TestOrderCreation:
    """Tests for order creation."""

    def test_create_order_single(self, registered_client: AcmeClient):
        """Should create order for single domain."""
        order = registered_client.create_order(domains=["example.com"])

        assert order.status == "pending"
        assert len(order.authorizations) == 1
        assert len(order.identifiers) == 1
        assert order.identifiers[0].value == "example.com"

    def test_create_order_multiple(self, registered_client: AcmeClient):
        """Should create order for multiple domains."""
        domains = ["example.com", "www.example.com"]
        order = registered_client.create_order(domains=domains)

        assert order.status == "pending"
        assert len(order.authorizations) == 2
        assert len(order.identifiers) == 2

    def test_create_order_wildcard(self, registered_client: AcmeClient):
        """Should create order for wildcard domain."""
        order = registered_client.create_order(domains=["*.example.com"])

        assert order.status == "pending"
        assert len(order.authorizations) == 1

    def test_create_order_wildcard_and_base(self, registered_client: AcmeClient):
        """Should create order for wildcard and base domain."""
        order = registered_client.create_order(domains=["*.example.com", "example.com"])

        assert order.status == "pending"
        # Wildcard and base domain may share authorization or have separate ones
        assert len(order.authorizations) >= 1

    def test_order_has_finalize_url(self, registered_client: AcmeClient):
        """Order should have finalize URL."""
        order = registered_client.create_order(domains=["example.com"])

        assert order.finalize is not None
        assert "finalize" in order.finalize


class TestAuthorizationFetching:
    """Tests for authorization fetching."""

    def test_fetch_authorizations(self, registered_client: AcmeClient):
        """Should fetch authorizations for an order."""
        order = registered_client.create_order(domains=["example.com"])
        authzs = registered_client.fetch_authorizations(order)

        assert len(authzs) == 1
        assert authzs[0].identifier.value == "example.com"
        assert authzs[0].status in ("pending", "valid")

    def test_authorization_has_challenges(self, registered_client: AcmeClient):
        """Authorization should have challenges."""
        order = registered_client.create_order(domains=["example.com"])
        authzs = registered_client.fetch_authorizations(order)

        assert len(authzs[0].challenges) > 0

    def test_get_dns01_challenge(self, registered_client: AcmeClient):
        """Should extract DNS-01 challenge from authorization."""
        order = registered_client.create_order(domains=["example.com"])
        authzs = registered_client.fetch_authorizations(order)

        challenge = registered_client.get_challenge(authzs[0], challenge_type="dns-01")

        assert challenge.type == "dns-01"
        assert challenge.token is not None
        assert challenge.url is not None

    def test_get_nonexistent_challenge_raises(self, registered_client: AcmeClient):
        """Should raise ValueError for nonexistent challenge type."""
        order = registered_client.create_order(domains=["example.com"])
        authzs = registered_client.fetch_authorizations(order)

        with pytest.raises(ValueError, match="not found"):
            registered_client.get_challenge(authzs[0], challenge_type="nonexistent-challenge")
