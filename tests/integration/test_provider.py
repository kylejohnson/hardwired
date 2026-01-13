"""Integration tests for DNS providers (requires pebble-challtestsrv)."""

import pytest

from hardwired.providers.test import TestProvider


@pytest.fixture
def test_provider(challtestsrv_url: str) -> TestProvider:
    """Create a TestProvider configured for challtestsrv."""
    return TestProvider(challtestsrv_url=challtestsrv_url)


class TestTestProviderIntegration:
    """Integration tests for TestProvider against pebble-challtestsrv."""

    def test_create_and_delete_dns_record(self, test_provider: TestProvider):
        """Should be able to create and delete DNS TXT records."""
        domain = "integration-test.example.com"
        token = "test-token-abc123"

        # Create record - should not raise
        test_provider.create_txt_record(domain, token)

        # Delete record - should not raise
        test_provider.delete_txt_record(domain, token)

    def test_create_multiple_records(self, test_provider: TestProvider):
        """Should be able to create multiple records for different domains."""
        domains = [
            ("domain1.example.com", "token1"),
            ("domain2.example.com", "token2"),
            ("domain3.example.com", "token3"),
        ]

        # Create all records
        for domain, token in domains:
            test_provider.create_txt_record(domain, token)

        # Delete all records
        for domain, token in domains:
            test_provider.delete_txt_record(domain, token)

    def test_wait_for_propagation_immediate(self, test_provider: TestProvider):
        """For test provider, propagation should be immediate."""
        result = test_provider.wait_for_propagation("example.com", "token", timeout=1)
        assert result is True

    def test_create_record_for_wildcard_domain(self, test_provider: TestProvider):
        """Should handle wildcard domain records correctly."""
        # Wildcard domains use the base domain for the challenge
        domain = "example.com"  # Not *.example.com
        token = "wildcard-token"

        test_provider.create_txt_record(domain, token)
        test_provider.delete_txt_record(domain, token)
