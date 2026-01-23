"""Integration tests for PowerDNS API error handling (requires PowerDNS in Docker).

These tests validate real API error responses from PowerDNS. They test errors that
can be triggered by client behavior (malformed requests, invalid zones, etc.).

For server-side errors that cannot be triggered by clients (500, 503, JSON parse errors),
see the mocked tests in tests/unit/test_providers.py::TestPowerDnsProviderMockedErrors.
"""

import httpx
import pytest

from hardwired.providers.powerdns import PowerDnsProvider


@pytest.fixture
def powerdns_provider(
    powerdns_api_url: str, powerdns_api_key: str, powerdns_test_zone: str
) -> PowerDnsProvider:
    """Create a PowerDnsProvider configured for test PowerDNS.

    The powerdns_test_zone fixture ensures the test zone exists.
    """
    return PowerDnsProvider(api_url=powerdns_api_url, api_key=powerdns_api_key)


class TestPowerDnsApiErrorsIntegration:
    """Integration tests for PowerDNS API errors using real API responses.

    These tests trigger actual error conditions in PowerDNS to verify the
    provider's error handling code paths with real HTTP responses.
    """

    def test_204_success_real_delete(self, powerdns_provider: PowerDnsProvider) -> None:
        """DELETE operations should return 204 and succeed.

        This tests the happy path for 204 responses using a real API call.
        """
        domain = "delete-test.example.org"
        token = "test-token"

        # Create a record first
        powerdns_provider.create_txt_record(domain, token)

        # Delete should succeed with 204 (no content)
        powerdns_provider.delete_txt_record(domain, token)

    def test_400_invalid_json(
        self, powerdns_api_url: str, powerdns_api_key: str, powerdns_test_zone: str
    ) -> None:
        """Invalid JSON payload should return 400 Bad Request.

        This tests the error handling for 400 responses using syntactically
        invalid JSON that cannot be parsed.
        """
        provider = PowerDnsProvider(api_url=powerdns_api_url, api_key=powerdns_api_key)
        headers = {
            "X-API-Key": powerdns_api_key,
            "Content-Type": "application/json",
        }

        # Send syntactically invalid JSON (unparseable)
        response = httpx.patch(
            f"{powerdns_api_url}/api/v1/servers/localhost/zones/{powerdns_test_zone}",
            headers=headers,
            content=b"{invalid_json",  # Malformed JSON
            timeout=30,
        )

        assert response.status_code == 400

        # Verify our provider raises ValueError with 'Bad Request'
        with pytest.raises(ValueError, match="Bad Request"):
            provider._handle_response(response, powerdns_test_zone)

    def test_404_nonexistent_zone(
        self, powerdns_api_url: str, powerdns_api_key: str, powerdns_test_zone: str
    ) -> None:
        """PATCH to non-existent zone should return 404 Not Found.

        This tests the error handling for 404 responses using a real API call
        to a zone that doesn't exist.
        """
        provider = PowerDnsProvider(api_url=powerdns_api_url, api_key=powerdns_api_key)
        headers = {
            "X-API-Key": powerdns_api_key,
            "Content-Type": "application/json",
        }

        nonexistent_zone = "nonexistent.invalid."
        payload = {
            "rrsets": [
                {
                    "name": f"_acme-challenge.test.{nonexistent_zone}",
                    "type": "TXT",
                    "ttl": 60,
                    "changetype": "REPLACE",
                    "records": [{"content": '"test"', "disabled": False}],
                }
            ]
        }

        response = httpx.patch(
            f"{powerdns_api_url}/api/v1/servers/localhost/zones/{nonexistent_zone}",
            headers=headers,
            json=payload,
            timeout=30,
        )

        assert response.status_code == 404

        # Verify our provider raises ValueError with 'Zone not found'
        with pytest.raises(ValueError, match="Zone not found"):
            provider._handle_response(response, nonexistent_zone)

    def test_422_invalid_record_data(
        self, powerdns_api_url: str, powerdns_api_key: str, powerdns_test_zone: str
    ) -> None:
        """Invalid record data should return 422 Unprocessable Entity.

        This tests the error handling for 422 responses using a real API call
        with semantically invalid data (negative TTL).
        """
        provider = PowerDnsProvider(api_url=powerdns_api_url, api_key=powerdns_api_key)
        headers = {
            "X-API-Key": powerdns_api_key,
            "Content-Type": "application/json",
        }

        # Send payload with invalid TTL (negative value)
        invalid_payload = {
            "rrsets": [
                {
                    "name": f"_acme-challenge.invalid-ttl.{powerdns_test_zone}",
                    "type": "TXT",
                    "ttl": -1,  # Invalid negative TTL
                    "changetype": "REPLACE",
                    "records": [{"content": '"test"', "disabled": False}],
                }
            ]
        }

        response = httpx.patch(
            f"{powerdns_api_url}/api/v1/servers/localhost/zones/{powerdns_test_zone}",
            headers=headers,
            json=invalid_payload,
            timeout=30,
        )

        assert response.status_code == 422

        # Verify our provider raises ValueError with 'Unprocessable Entity'
        with pytest.raises(ValueError, match="Unprocessable Entity"):
            provider._handle_response(response, powerdns_test_zone)
