"""Unit tests for DNS providers."""

import json

import httpx
import pytest
import respx

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

    @respx.mock
    def test_find_zone_exact_match(self):
        """Should find zone when domain matches zone exactly."""
        respx.get("http://localhost:8081/api/v1/servers/localhost/zones").mock(
            return_value=httpx.Response(200, json=[{"name": "example.org."}])
        )
        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")

        result = provider._find_zone("example.org")

        assert result == "example.org."

    @respx.mock
    def test_find_zone_subdomain_match(self):
        """Should find parent zone for subdomain."""
        respx.get("http://localhost:8081/api/v1/servers/localhost/zones").mock(
            return_value=httpx.Response(200, json=[{"name": "example.org."}])
        )
        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")

        result = provider._find_zone("sub.example.org")

        assert result == "example.org."

    @respx.mock
    def test_find_zone_deep_subdomain(self):
        """Should find zone for deeply nested subdomain."""
        respx.get("http://localhost:8081/api/v1/servers/localhost/zones").mock(
            return_value=httpx.Response(200, json=[{"name": "example.org."}])
        )
        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")

        result = provider._find_zone("a.b.c.example.org")

        assert result == "example.org."

    @respx.mock
    def test_find_zone_prefers_most_specific(self):
        """Should prefer more specific zone when multiple match."""
        respx.get("http://localhost:8081/api/v1/servers/localhost/zones").mock(
            return_value=httpx.Response(
                200, json=[{"name": "example.org."}, {"name": "sub.example.org."}]
            )
        )
        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")

        result = provider._find_zone("host.sub.example.org")

        assert result == "sub.example.org."

    @respx.mock
    def test_find_zone_no_match_raises_valueerror(self):
        """Should raise ValueError when no zone matches."""
        respx.get("http://localhost:8081/api/v1/servers/localhost/zones").mock(
            return_value=httpx.Response(200, json=[{"name": "example.org."}])
        )
        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")

        with pytest.raises(ValueError, match="No zone found for domain"):
            provider._find_zone("other.com")

    @respx.mock
    def test_find_zone_handles_trailing_dot(self):
        """Should handle domain with trailing dot."""
        respx.get("http://localhost:8081/api/v1/servers/localhost/zones").mock(
            return_value=httpx.Response(200, json=[{"name": "example.org."}])
        )
        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")

        result = provider._find_zone("example.org.")

        assert result == "example.org."

    @respx.mock
    def test_find_zone_handles_no_trailing_dot(self):
        """Should handle domain without trailing dot."""
        respx.get("http://localhost:8081/api/v1/servers/localhost/zones").mock(
            return_value=httpx.Response(200, json=[{"name": "example.org."}])
        )
        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")

        result = provider._find_zone("example.org")

        assert result == "example.org."


class TestPowerDnsProviderErrorHandling:
    """Unit tests for PowerDNS API error handling."""

    def test_handle_response_204_success(self):
        """204 should not raise."""
        from unittest.mock import MagicMock

        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")
        mock_response = MagicMock()
        mock_response.status_code = 204

        # Should not raise
        provider._handle_response(mock_response, "example.org.")

    def test_handle_response_400_bad_request(self):
        """400 should raise ValueError with 'Bad Request'."""
        from unittest.mock import MagicMock

        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": "Invalid JSON format"}
        mock_response.text = "Invalid JSON format"

        with pytest.raises(ValueError, match="Bad Request: Invalid JSON format"):
            provider._handle_response(mock_response, "example.org.")

    def test_handle_response_404_not_found(self):
        """404 should raise ValueError with 'Zone not found'."""
        from unittest.mock import MagicMock

        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.json.return_value = {"error": "Zone example.org. not found"}
        mock_response.text = "Zone example.org. not found"

        with pytest.raises(ValueError, match="Zone not found: Zone example.org. not found"):
            provider._handle_response(mock_response, "example.org.")

    def test_handle_response_422_unprocessable(self):
        """422 should raise ValueError with 'Unprocessable Entity'."""
        from unittest.mock import MagicMock

        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")
        mock_response = MagicMock()
        mock_response.status_code = 422
        mock_response.json.return_value = {"error": "Invalid record data"}
        mock_response.text = "Invalid record data"

        with pytest.raises(ValueError, match="Unprocessable Entity: Invalid record data"):
            provider._handle_response(mock_response, "example.org.")

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

    @respx.mock
    def test_common_dns_record_replace_success(self):
        """REPLACE changetype with 204 should succeed."""
        respx.get("http://localhost:8081/api/v1/servers/localhost/zones").mock(
            return_value=httpx.Response(200, json=[{"name": "example.org."}])
        )
        respx.patch("http://localhost:8081/api/v1/servers/localhost/zones/example.org.").mock(
            return_value=httpx.Response(204)
        )
        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")

        # Should not raise
        provider._common_dns_record("test.example.org", "test-token", "REPLACE")

    @respx.mock
    def test_common_dns_record_delete_success(self):
        """DELETE changetype with 204 should succeed."""
        respx.get("http://localhost:8081/api/v1/servers/localhost/zones").mock(
            return_value=httpx.Response(200, json=[{"name": "example.org."}])
        )
        respx.patch("http://localhost:8081/api/v1/servers/localhost/zones/example.org.").mock(
            return_value=httpx.Response(204)
        )
        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")

        # Should not raise
        provider._common_dns_record("test.example.org", "test-token", "DELETE")

    def test_common_dns_record_invalid_changetype(self):
        """Invalid changetype should raise ValueError."""
        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")

        with pytest.raises(ValueError, match="Invalid changetype: INVALID"):
            provider._common_dns_record("example.org", "token", "INVALID")

    @respx.mock
    def test_common_dns_record_constructs_correct_payload_replace(self):
        """REPLACE should include ttl and records in payload."""
        respx.get("http://localhost:8081/api/v1/servers/localhost/zones").mock(
            return_value=httpx.Response(200, json=[{"name": "example.org."}])
        )
        patch_route = respx.patch(
            "http://localhost:8081/api/v1/servers/localhost/zones/example.org."
        ).mock(return_value=httpx.Response(204))

        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")

        provider._common_dns_record("test.example.org", "my-token", "REPLACE")

        # Verify the request
        assert patch_route.called
        request = patch_route.calls.last.request
        payload = json.loads(request.content)

        assert len(payload["rrsets"]) == 1
        rrset = payload["rrsets"][0]
        assert rrset["name"] == "_acme-challenge.test.example.org."
        assert rrset["type"] == "TXT"
        assert rrset["changetype"] == "REPLACE"
        assert rrset["ttl"] == 60
        assert len(rrset["records"]) == 1
        assert rrset["records"][0]["content"] == '"my-token"'
        assert rrset["records"][0]["disabled"] is False

    @respx.mock
    def test_common_dns_record_constructs_correct_payload_delete(self):
        """DELETE should not include ttl or records in payload."""
        respx.get("http://localhost:8081/api/v1/servers/localhost/zones").mock(
            return_value=httpx.Response(200, json=[{"name": "example.org."}])
        )
        patch_route = respx.patch(
            "http://localhost:8081/api/v1/servers/localhost/zones/example.org."
        ).mock(return_value=httpx.Response(204))

        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")

        provider._common_dns_record("test.example.org", "my-token", "DELETE")

        # Verify the request
        assert patch_route.called
        request = patch_route.calls.last.request
        payload = json.loads(request.content)

        assert len(payload["rrsets"]) == 1
        rrset = payload["rrsets"][0]
        assert rrset["name"] == "_acme-challenge.test.example.org."
        assert rrset["type"] == "TXT"
        assert rrset["changetype"] == "DELETE"
        assert "ttl" not in rrset
        assert "records" not in rrset

    @respx.mock
    def test_common_dns_record_400_raises_valueerror(self):
        """400 response should raise ValueError with 'Bad Request'."""
        respx.get("http://localhost:8081/api/v1/servers/localhost/zones").mock(
            return_value=httpx.Response(200, json=[{"name": "example.org."}])
        )
        respx.patch("http://localhost:8081/api/v1/servers/localhost/zones/example.org.").mock(
            return_value=httpx.Response(400, json={"error": "Malformed request"})
        )
        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")

        with pytest.raises(ValueError, match="Bad Request: Malformed request"):
            provider._common_dns_record("test.example.org", "token", "REPLACE")

    @respx.mock
    def test_common_dns_record_404_raises_valueerror(self):
        """404 response should raise ValueError with 'Zone not found'."""
        respx.get("http://localhost:8081/api/v1/servers/localhost/zones").mock(
            return_value=httpx.Response(200, json=[{"name": "example.org."}])
        )
        respx.patch("http://localhost:8081/api/v1/servers/localhost/zones/example.org.").mock(
            return_value=httpx.Response(404, json={"error": "Zone not in database"})
        )
        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="secret")

        with pytest.raises(ValueError, match="Zone not found: Zone not in database"):
            provider._common_dns_record("test.example.org", "token", "REPLACE")

    @respx.mock
    def test_common_dns_record_uses_correct_headers(self):
        """Should send X-API-Key and Content-Type headers."""
        respx.get("http://localhost:8081/api/v1/servers/localhost/zones").mock(
            return_value=httpx.Response(200, json=[{"name": "example.org."}])
        )
        patch_route = respx.patch(
            "http://localhost:8081/api/v1/servers/localhost/zones/example.org."
        ).mock(return_value=httpx.Response(204))

        provider = PowerDnsProvider(api_url="http://localhost:8081", api_key="my-secret-key")

        provider._common_dns_record("test.example.org", "token", "REPLACE")

        request = patch_route.calls.last.request
        assert request.headers["X-API-Key"] == "my-secret-key"
        assert request.headers["Content-Type"] == "application/json"
