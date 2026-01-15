"""Integration tests for authorization deactivation (requires pebble + challtestsrv)."""

import pytest

from hardwired import AcmeClient
from hardwired.crypto import generate_rsa_key
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


class TestAuthorizationDeactivation:
    """Tests for authorization deactivation (RFC 8555 Section 7.5.2)."""

    def test_deactivate_authorization(self, client: AcmeClient):
        """Should deactivate a valid authorization."""
        # Create order to get authorization
        order = client.create_order(domains=["deactivate-test.example.com"])
        authorizations = client.fetch_authorizations(order)
        authz = authorizations[0]

        # Get the URL (attached during fetch)
        authz_url = getattr(authz, "_url", None)
        assert authz_url is not None

        # Deactivate - should not raise
        client.deactivate_authorization(authz_url)

    def test_deactivate_authorization_returns_updated_status(self, client: AcmeClient):
        """Deactivating should return authorization with deactivated status."""
        order = client.create_order(domains=["deactivate-status.example.com"])
        authorizations = client.fetch_authorizations(order)
        authz = authorizations[0]
        authz_url = getattr(authz, "_url", None)
        assert authz_url is not None

        # Deactivate and check returned authorization
        updated_authz = client.deactivate_authorization(authz_url)
        assert updated_authz.status == "deactivated"

    def test_deactivate_after_obtaining_certificate(self, client: AcmeClient):
        """Should be able to deactivate authorization after obtaining certificate."""
        # Get certificate (which validates the authorization)
        result = client.obtain_certificate(
            domains=["deactivate-after-cert.example.com", "*.deactivate-after-cert.example.com"]
        )

        # Should have 2 authorization infos (one for base domain, one for wildcard)
        # Both are for the same domain identifier but one has wildcard=true
        assert len(result.authorizations) == 2

        # Deactivate all authorizations
        for authz_info in result.authorizations:
            updated_authz = client.deactivate_authorization(authz_info.url)
            assert updated_authz.status == "deactivated"

    def test_deactivate_wildcard_authorization(self, client: AcmeClient):
        """Should deactivate authorization for wildcard domain."""
        # Create order with wildcard
        order = client.create_order(
            domains=["deactivate-wild.example.com", "*.deactivate-wild.example.com"]
        )
        authorizations = client.fetch_authorizations(order)

        # Should have 2 authorizations (one regular, one wildcard)
        assert len(authorizations) == 2

        # Find the wildcard authorization
        wildcard_authz = None
        for authz in authorizations:
            if authz.wildcard:
                wildcard_authz = authz
                break
        assert wildcard_authz is not None

        # Deactivate the wildcard authorization
        authz_url = getattr(wildcard_authz, "_url", None)
        assert authz_url is not None
        updated_authz = client.deactivate_authorization(authz_url)
        assert updated_authz.status == "deactivated"
