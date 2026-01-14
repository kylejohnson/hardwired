"""Integration tests for challenge validation (requires pebble + challtestsrv)."""

import pytest

from hardwired import AcmeClient
from hardwired.crypto import generate_rsa_key
from hardwired.exceptions import AcmeError
from hardwired.providers.pebble import PebbleProvider


@pytest.fixture
def client_with_order(pebble_directory_url: str, challtestsrv_url: str, pebble_ca_cert: str):
    """Create a registered client with a pending order."""
    client = AcmeClient(
        directory_url=pebble_directory_url,
        account_key=generate_rsa_key(2048),
        dns_provider=PebbleProvider(challtestsrv_url),
        ca_cert=pebble_ca_cert,
    )
    client.register_account(email="test@example.com")
    order = client.create_order(domains=["test.example.com"])
    return client, order


class TestChallengeCompletion:
    """Tests for challenge completion flow."""

    def test_complete_dns01_challenge(self, client_with_order):
        """Should complete DNS-01 challenge successfully."""
        client, order = client_with_order
        authzs = client.fetch_authorizations(order)
        challenge = client.get_challenge(authzs[0], "dns-01")

        # Complete the challenge (sets DNS, responds, polls)
        result = client.complete_challenge(challenge, authzs[0])

        assert result.status == "valid"

    def test_complete_multiple_challenges(
        self, pebble_directory_url: str, challtestsrv_url: str, pebble_ca_cert: str
    ):
        """Should complete challenges for multiple domains."""
        client = AcmeClient(
            directory_url=pebble_directory_url,
            account_key=generate_rsa_key(2048),
            dns_provider=PebbleProvider(challtestsrv_url),
            ca_cert=pebble_ca_cert,
        )
        client.register_account()

        domains = ["one.example.com", "two.example.com"]
        order = client.create_order(domains=domains)
        authzs = client.fetch_authorizations(order)

        # Complete all challenges
        for authz in authzs:
            challenge = client.get_challenge(authz, "dns-01")
            result = client.complete_challenge(challenge, authz)
            assert result.status == "valid"

    def test_challenge_without_dns_setup_fails(self, client_with_order):
        """Challenge should fail without proper DNS setup."""
        client, order = client_with_order
        authzs = client.fetch_authorizations(order)
        challenge = client.get_challenge(authzs[0], "dns-01")

        # Skip DNS setup - should fail validation
        with pytest.raises(AcmeError):
            client.complete_challenge(challenge, authzs[0], skip_dns_setup=True)

    def test_wildcard_challenge(
        self, pebble_directory_url: str, challtestsrv_url: str, pebble_ca_cert: str
    ):
        """Should complete challenge for wildcard domain."""
        client = AcmeClient(
            directory_url=pebble_directory_url,
            account_key=generate_rsa_key(2048),
            dns_provider=PebbleProvider(challtestsrv_url),
            ca_cert=pebble_ca_cert,
        )
        client.register_account()

        order = client.create_order(domains=["*.wildcard.example.com"])
        authzs = client.fetch_authorizations(order)
        challenge = client.get_challenge(authzs[0], "dns-01")

        result = client.complete_challenge(challenge, authzs[0])
        assert result.status == "valid"
