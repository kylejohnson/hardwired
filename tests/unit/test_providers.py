"""Unit tests for DNS providers."""

from hardwired.providers.base import DnsProvider
from hardwired.providers.pebble import PebbleProvider
from hardwired.providers.powerdns import PowerDnsProvider


class TestDnsProviderInterface:
    """Tests for DnsProvider abstract interface."""

    def test_provider_implements_interface(self):
        """PebbleProvider should implement DnsProvider interface."""
        provider = PebbleProvider(challtestsrv_url="http://localhost:8055")
        assert isinstance(provider, DnsProvider)

    def test_provider_has_required_methods(self):
        """Provider should have all required methods."""
        provider = PebbleProvider(challtestsrv_url="http://localhost:8055")

        assert hasattr(provider, "create_txt_record")
        assert hasattr(provider, "delete_txt_record")
        assert hasattr(provider, "wait_for_propagation")
        assert callable(provider.create_txt_record)
        assert callable(provider.delete_txt_record)
        assert callable(provider.wait_for_propagation)


class TestPebbleProvider:
    """Tests for PebbleProvider (pebble-challtestsrv).

    Note: HTTP interaction tests have been moved to integration tests
    (tests/integration/test_provider.py) where they run against real
    pebble-challtestsrv for proper validation.
    """

    def test_wait_for_propagation_returns_true(self):
        """wait_for_propagation should return True immediately for test provider."""
        provider = PebbleProvider(challtestsrv_url="http://localhost:8055")

        result = provider.wait_for_propagation("example.com", "token", timeout=1)

        assert result is True

    def test_provider_stores_url(self):
        """Provider should store challtestsrv URL."""
        url = "http://custom:9999"
        provider = PebbleProvider(challtestsrv_url=url)

        assert provider.challtestsrv_url == url


class TestPowerDnsProviderInterface:
    """Tests for PowerDnsProvider interface compliance."""

    def test_provider_implements_interface(self):
        """PowerDnsProvider should implement DnsProvider interface."""
        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")
        assert isinstance(provider, DnsProvider)

    def test_provider_has_required_methods(self):
        """Provider should have all required methods."""
        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")

        assert hasattr(provider, "create_txt_record")
        assert hasattr(provider, "delete_txt_record")
        assert hasattr(provider, "wait_for_propagation")
        assert callable(provider.create_txt_record)
        assert callable(provider.delete_txt_record)
        assert callable(provider.wait_for_propagation)


class TestPowerDnsProvider:
    """Unit tests for PowerDnsProvider configuration."""

    def test_wait_for_propagation_returns_true(self):
        """wait_for_propagation should return True immediately."""
        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")

        result = provider.wait_for_propagation("example.com", "token", timeout=1)

        assert result is True

    def test_provider_stores_configuration(self):
        """Provider should store API configuration."""
        provider = PowerDnsProvider(
            api_url="http://pdns.example.com:8081",
            api_key="my-api-key",
            server_id="custom-server",
            timeout=60,
        )

        assert provider.api_url == "http://pdns.example.com:8081"
        assert provider.api_key == "my-api-key"
        assert provider.server_id == "custom-server"
        assert provider.timeout == 60

    def test_api_url_trailing_slash_stripped(self):
        """Provider should strip trailing slash from API URL."""
        provider = PowerDnsProvider(api_url="http://localhost:8081/", api_key="secret")

        assert provider.api_url == "http://localhost:8081"

    def test_default_server_id(self):
        """Provider should use 'localhost' as default server_id."""
        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")

        assert provider.server_id == "localhost"

    def test_default_timeout(self):
        """Provider should use 30 as default timeout."""
        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")

        assert provider.timeout == 30
