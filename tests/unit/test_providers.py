"""Unit tests for DNS providers."""

from hardwired.providers.base import DnsProvider
from hardwired.providers.test import TestProvider


class TestDnsProviderInterface:
    """Tests for DnsProvider abstract interface."""

    def test_provider_implements_interface(self):
        """TestProvider should implement DnsProvider interface."""
        provider = TestProvider(challtestsrv_url="http://localhost:8055")
        assert isinstance(provider, DnsProvider)

    def test_provider_has_required_methods(self):
        """Provider should have all required methods."""
        provider = TestProvider(challtestsrv_url="http://localhost:8055")

        assert hasattr(provider, "create_txt_record")
        assert hasattr(provider, "delete_txt_record")
        assert hasattr(provider, "wait_for_propagation")
        assert callable(provider.create_txt_record)
        assert callable(provider.delete_txt_record)
        assert callable(provider.wait_for_propagation)


class TestTestProvider:
    """Tests for TestProvider (pebble-challtestsrv).

    Note: HTTP interaction tests have been moved to integration tests
    (tests/integration/test_provider.py) where they run against real
    pebble-challtestsrv for proper validation.
    """

    def test_wait_for_propagation_returns_true(self):
        """wait_for_propagation should return True immediately for test provider."""
        provider = TestProvider(challtestsrv_url="http://localhost:8055")

        result = provider.wait_for_propagation("example.com", "token", timeout=1)

        assert result is True

    def test_provider_stores_url(self):
        """Provider should store challtestsrv URL."""
        url = "http://custom:9999"
        provider = TestProvider(challtestsrv_url=url)

        assert provider.challtestsrv_url == url
