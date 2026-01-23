"""Unit tests for DNS providers."""

import pytest

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


class TestPowerDnsProviderFindZone:
    """Unit tests for PowerDnsProvider._find_zone() method."""

    def test_find_zone_exact_match(
        self, powerdns_api_url: str, powerdns_api_key: str, powerdns_test_zone: str
    ):
        """Should find zone when domain matches zone exactly."""
        provider = PowerDnsProvider(api_url=powerdns_api_url, api_key=powerdns_api_key)

        result = provider._find_zone("example.org")

        assert result == "example.org."

    def test_find_zone_subdomain_match(
        self, powerdns_api_url: str, powerdns_api_key: str, powerdns_test_zone: str
    ):
        """Should find parent zone for subdomain."""
        provider = PowerDnsProvider(api_url=powerdns_api_url, api_key=powerdns_api_key)

        result = provider._find_zone("sub.example.org")

        assert result == "example.org."

    def test_find_zone_deep_subdomain(
        self, powerdns_api_url: str, powerdns_api_key: str, powerdns_test_zone: str
    ):
        """Should find zone for deeply nested subdomain."""
        provider = PowerDnsProvider(api_url=powerdns_api_url, api_key=powerdns_api_key)

        result = provider._find_zone("a.b.c.example.org")

        assert result == "example.org."

    def test_find_zone_no_match_raises_valueerror(
        self, powerdns_api_url: str, powerdns_api_key: str, powerdns_test_zone: str
    ):
        """Should raise ValueError when no zone matches."""
        provider = PowerDnsProvider(api_url=powerdns_api_url, api_key=powerdns_api_key)

        with pytest.raises(ValueError, match="No zone found for domain"):
            provider._find_zone("nonexistent.tld")

    def test_find_zone_handles_trailing_dot(
        self, powerdns_api_url: str, powerdns_api_key: str, powerdns_test_zone: str
    ):
        """Should handle domain with trailing dot."""
        provider = PowerDnsProvider(api_url=powerdns_api_url, api_key=powerdns_api_key)

        result = provider._find_zone("example.org.")

        assert result == "example.org."

    def test_find_zone_handles_no_trailing_dot(
        self, powerdns_api_url: str, powerdns_api_key: str, powerdns_test_zone: str
    ):
        """Should handle domain without trailing dot."""
        provider = PowerDnsProvider(api_url=powerdns_api_url, api_key=powerdns_api_key)

        result = provider._find_zone("example.org")

        assert result == "example.org."


class TestPowerDnsProviderMockedErrors:
    """Unit tests for PowerDNS error handling that require mocked responses.

    These tests cover server-side errors that cannot be triggered by client behavior:
    - 500 Internal Server Error (database failures, etc.)
    - 503 Service Unavailable (maintenance, overload)
    - Malformed JSON responses

    For client-triggerable errors (400, 404, 422), see the integration tests in:
    tests/integration/test_powerdns_error_handling.py::TestPowerDnsApiErrorsIntegration
    """

    def test_handle_response_500_server_error(self):
        """500 should raise ValueError with 'Server Error'."""
        from unittest.mock import MagicMock

        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.json.return_value = {"error": "Database connection failed"}
        mock_response.text = "Database connection failed"

        with pytest.raises(ValueError, match="Server Error: Database connection failed"):
            provider._handle_response(mock_response, "example.org.")

    def test_handle_response_unexpected_error(self):
        """Unexpected status code should raise ValueError with status code."""
        from unittest.mock import MagicMock

        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")
        mock_response = MagicMock()
        mock_response.status_code = 503
        mock_response.json.return_value = {"error": "Service unavailable"}
        mock_response.text = "Service unavailable"

        with pytest.raises(ValueError, match=r"Unexpected error \(503\): Service unavailable"):
            provider._handle_response(mock_response, "example.org.")

    def test_handle_response_json_parse_error_fallback(self):
        """Should fallback to response.text when JSON parsing fails."""
        from unittest.mock import MagicMock

        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_response.text = "Plain text error message"

        with pytest.raises(ValueError, match="Bad Request: Plain text error message"):
            provider._handle_response(mock_response, "example.org.")


class TestPowerDnsProviderCommonRecord:
    """Unit tests for _common_dns_record() method."""

    def test_common_dns_record_replace_success(
        self, powerdns_api_url: str, powerdns_api_key: str, powerdns_test_zone: str
    ):
        """REPLACE changetype with 204 should succeed."""
        provider = PowerDnsProvider(api_url=powerdns_api_url, api_key=powerdns_api_key)

        # Should not raise
        provider._common_dns_record("test.example.org", "test-token", "REPLACE")

    def test_common_dns_record_delete_success(
        self, powerdns_api_url: str, powerdns_api_key: str, powerdns_test_zone: str
    ):
        """DELETE changetype with 204 should succeed."""
        provider = PowerDnsProvider(api_url=powerdns_api_url, api_key=powerdns_api_key)

        # First create a record, then delete it
        provider._common_dns_record("test.example.org", "test-token", "REPLACE")

        # Should not raise
        provider._common_dns_record("test.example.org", "test-token", "DELETE")

    def test_common_dns_record_invalid_changetype(self):
        """Invalid changetype should raise ValueError."""
        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")

        with pytest.raises(ValueError, match="Invalid changetype: INVALID"):
            provider._common_dns_record("example.org", "token", "INVALID")
