"""Integration tests for ACME account operations (requires pebble)."""

import pytest

from hardwired import AcmeClient
from hardwired.crypto import generate_rsa_key
from hardwired.providers.test import TestProvider


@pytest.fixture
def client(pebble_directory_url: str, challtestsrv_url: str, pebble_ca_cert: str) -> AcmeClient:
    """Create an AcmeClient configured for pebble."""
    return AcmeClient(
        directory_url=pebble_directory_url,
        account_key=generate_rsa_key(2048),
        dns_provider=TestProvider(challtestsrv_url),
        ca_cert=pebble_ca_cert,
    )


class TestDirectory:
    """Tests for directory fetching."""

    def test_fetch_directory(self, client: AcmeClient):
        """Client should fetch and parse the ACME directory."""
        directory = client.directory

        assert directory.new_account is not None
        assert directory.new_order is not None
        assert directory.new_nonce is not None
        assert directory.revoke_cert is not None
        assert directory.key_change is not None

    def test_directory_is_cached(self, client: AcmeClient):
        """Directory should be cached after first fetch."""
        directory1 = client.directory
        directory2 = client.directory

        # Should be the same object (cached)
        assert directory1 is directory2


class TestNonce:
    """Tests for nonce management."""

    def test_get_nonce(self, client: AcmeClient):
        """Client should be able to get a nonce."""
        nonce = client._get_nonce()

        assert nonce is not None
        assert len(nonce) > 0

    def test_nonce_is_consumed(self, client: AcmeClient):
        """Nonce should be consumed after use."""
        # Get initial nonce
        nonce1 = client._get_nonce()

        # Make a request that uses the nonce (register account)
        client.register_account(email="test@example.com")

        # Get another nonce
        nonce2 = client._get_nonce()

        # Should be different nonces
        assert nonce1 != nonce2


class TestAccountRegistration:
    """Tests for account registration."""

    def test_register_account_new(self, client: AcmeClient):
        """Should be able to register a new account."""
        account = client.register_account(email="test@example.com")

        assert account.status == "valid"
        assert client.account_url is not None

    def test_register_account_with_contact(self, client: AcmeClient):
        """Account should be registered with contact email."""
        account = client.register_account(email="admin@example.com")

        assert account.status == "valid"
        assert account.contact is not None
        assert "mailto:admin@example.com" in account.contact

    def test_register_account_existing(
        self, pebble_directory_url: str, challtestsrv_url: str, pebble_ca_cert: str
    ):
        """Should find existing account with same key."""
        # Create key that will be reused
        account_key = generate_rsa_key(2048)

        # First client - register new account
        client1 = AcmeClient(
            directory_url=pebble_directory_url,
            account_key=account_key,
            dns_provider=TestProvider(challtestsrv_url),
            ca_cert=pebble_ca_cert,
        )
        client1.register_account(email="test@example.com")
        url1 = client1.account_url

        # Second client with same key - should find existing account
        client2 = AcmeClient(
            directory_url=pebble_directory_url,
            account_key=account_key,
            dns_provider=TestProvider(challtestsrv_url),
            ca_cert=pebble_ca_cert,
        )
        account2 = client2.register_account()

        assert account2.status == "valid"
        assert client2.account_url == url1

    def test_register_account_no_email(self, client: AcmeClient):
        """Should be able to register without email."""
        account = client.register_account()

        assert account.status == "valid"

    def test_register_account_terms_agreed(self, client: AcmeClient):
        """Account registration should agree to terms."""
        account = client.register_account(email="test@example.com")

        # Account should be valid (terms were agreed)
        assert account.status == "valid"
