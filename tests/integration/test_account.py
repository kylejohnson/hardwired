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


class TestBadNonceRetry:
    """Tests for bad nonce retry behavior."""

    def test_bad_nonce_retry_succeeds(
        self, pebble_directory_url: str, challtestsrv_url: str, pebble_ca_cert: str
    ):
        """Client should automatically retry on bad nonce errors.

        This test forces a stale nonce and verifies the client
        successfully retries with a fresh nonce.
        """
        client = AcmeClient(
            directory_url=pebble_directory_url,
            account_key=generate_rsa_key(2048),
            dns_provider=TestProvider(challtestsrv_url),
            ca_cert=pebble_ca_cert,
        )

        # Register account first
        client.register_account(email="test@example.com")

        # Force a stale nonce by setting an invalid one
        client._nonce = "invalid-stale-nonce-that-will-be-rejected"

        # This request should succeed because the client retries on badNonce
        # Creating an order will use the stale nonce, get rejected, and retry
        order = client.create_order(domains=["test-retry.example.com"])

        # If we get here, the retry worked
        assert order.status == "pending"

    def test_bad_nonce_retry_multiple_times(
        self, pebble_directory_url: str, challtestsrv_url: str, pebble_ca_cert: str
    ):
        """Client should handle consecutive requests with stale nonces.

        Each request that gets a bad nonce should retry independently.
        """
        client = AcmeClient(
            directory_url=pebble_directory_url,
            account_key=generate_rsa_key(2048),
            dns_provider=TestProvider(challtestsrv_url),
            ca_cert=pebble_ca_cert,
        )

        # Register account
        client.register_account()

        # Make multiple requests, each with a forced stale nonce
        for i in range(3):
            client._nonce = f"stale-nonce-{i}"
            order = client.create_order(domains=[f"test-{i}.example.com"])
            assert order.status == "pending"


class TestAccountKeyRollover:
    """Tests for account key rollover (RFC 8555 Section 7.3.5)."""

    def test_account_key_rollover(
        self, pebble_directory_url: str, challtestsrv_url: str, pebble_ca_cert: str
    ):
        """Should roll over to a new account key."""
        from hardwired.crypto import generate_ecdsa_key

        # Create client with initial RSA key
        old_key = generate_rsa_key(2048)
        client = AcmeClient(
            directory_url=pebble_directory_url,
            account_key=old_key,
            dns_provider=TestProvider(challtestsrv_url),
            ca_cert=pebble_ca_cert,
        )
        client.register_account(email="rollover@example.com")

        # Generate new ECDSA key and roll over
        new_key = generate_ecdsa_key()
        client.rollover_key(new_key)

        # Verify new key works - should be able to create orders
        order = client.create_order(domains=["rollover-test.example.com"])
        assert order is not None
        assert order.status == "pending"

    def test_account_key_rollover_same_algorithm(
        self, pebble_directory_url: str, challtestsrv_url: str, pebble_ca_cert: str
    ):
        """Should roll over to a new key of the same algorithm."""
        # Create client with initial key
        old_key = generate_rsa_key(2048)
        client = AcmeClient(
            directory_url=pebble_directory_url,
            account_key=old_key,
            dns_provider=TestProvider(challtestsrv_url),
            ca_cert=pebble_ca_cert,
        )
        client.register_account()

        # Roll over to another RSA key
        new_key = generate_rsa_key(2048)
        client.rollover_key(new_key)

        # Verify new key works
        order = client.create_order(domains=["rollover-same.example.com"])
        assert order.status == "pending"


class TestAccountDeactivation:
    """Tests for account deactivation (RFC 8555 Section 7.3.6)."""

    def test_account_deactivation(
        self, pebble_directory_url: str, challtestsrv_url: str, pebble_ca_cert: str
    ):
        """Should deactivate account (irreversible)."""
        # Create fresh account for this test
        key = generate_rsa_key(2048)
        client = AcmeClient(
            directory_url=pebble_directory_url,
            account_key=key,
            dns_provider=TestProvider(challtestsrv_url),
            ca_cert=pebble_ca_cert,
        )
        client.register_account(email="deactivate@example.com")

        # Deactivate
        client.deactivate_account()

        # Verify account is deactivated - creating orders should fail
        from hardwired.exceptions import AcmeError

        with pytest.raises(AcmeError):
            client.create_order(domains=["deactivated-test.example.com"])
