"""Integration tests for PowerDNS provider (requires PowerDNS in Docker)."""

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


class TestPowerDnsProviderIntegration:
    """Integration tests for PowerDnsProvider against PowerDNS."""

    def test_create_and_delete_dns_record(self, powerdns_provider: PowerDnsProvider):
        """Should be able to create and delete DNS TXT records."""
        domain = "test.example.org"
        token = "test-token-abc123"

        # Create record - should not raise
        powerdns_provider.create_txt_record(domain, token)

        # Delete record - should not raise
        powerdns_provider.delete_txt_record(domain, token)

    def test_create_subdomain_record(self, powerdns_provider: PowerDnsProvider):
        """Should create record for subdomain in correct zone."""
        domain = "deep.sub.test.example.org"
        token = "subdomain-token"

        powerdns_provider.create_txt_record(domain, token)
        powerdns_provider.delete_txt_record(domain, token)

    def test_create_multiple_records(self, powerdns_provider: PowerDnsProvider):
        """Should be able to create multiple records for different domains."""
        domains = [
            ("domain1.example.org", "token1"),
            ("domain2.example.org", "token2"),
        ]

        # Create all records
        for domain, token in domains:
            powerdns_provider.create_txt_record(domain, token)

        # Delete all records
        for domain, token in domains:
            powerdns_provider.delete_txt_record(domain, token)

    def test_replace_existing_record(self, powerdns_provider: PowerDnsProvider):
        """Should replace existing record when creating with same name."""
        domain = "replace.example.org"

        powerdns_provider.create_txt_record(domain, "first-token")
        powerdns_provider.create_txt_record(domain, "second-token")
        powerdns_provider.delete_txt_record(domain, "second-token")

    def test_wait_for_propagation_immediate(self, powerdns_provider: PowerDnsProvider):
        """For PowerDNS, propagation should be immediate."""
        result = powerdns_provider.wait_for_propagation("example.org", "token", timeout=1)
        assert result is True

    def test_zone_not_found_raises_error(self, powerdns_provider: PowerDnsProvider):
        """Should raise ValueError for domain with no matching zone."""
        with pytest.raises(ValueError, match="No zone found"):
            powerdns_provider.create_txt_record("unknown.nonexistent.tld", "token")

    def test_create_record_for_wildcard_domain(self, powerdns_provider: PowerDnsProvider):
        """Should handle wildcard domain records correctly."""
        # Wildcard domains use the base domain for the challenge
        domain = "example.org"  # Not *.example.org
        token = "wildcard-token"

        powerdns_provider.create_txt_record(domain, token)
        powerdns_provider.delete_txt_record(domain, token)

    def test_create_record_verifiable_via_api(
        self,
        powerdns_provider: PowerDnsProvider,
        powerdns_api_url: str,
        powerdns_api_key: str,
    ):
        """Created record should be verifiable via direct API call."""
        domain = "verify.example.org"
        token = "verify-token-123"

        powerdns_provider.create_txt_record(domain, token)

        try:
            # Verify record exists via direct API call
            headers = {"X-API-Key": powerdns_api_key}
            response = httpx.get(
                f"{powerdns_api_url}/api/v1/servers/localhost/zones/example.org.",
                headers=headers,
                timeout=30,
            )
            zone_data = response.json()

            # Find our TXT record in rrsets
            txt_records = [
                rrset
                for rrset in zone_data.get("rrsets", [])
                if rrset["name"] == f"_acme-challenge.{domain}." and rrset["type"] == "TXT"
            ]
            assert len(txt_records) == 1
            assert f'"{token}"' in txt_records[0]["records"][0]["content"]
        finally:
            # Cleanup
            powerdns_provider.delete_txt_record(domain, token)

    def test_delete_record_verifiable_via_api(
        self,
        powerdns_provider: PowerDnsProvider,
        powerdns_api_url: str,
        powerdns_api_key: str,
    ):
        """Deleted record should not exist via direct API call."""
        domain = "delete-verify.example.org"
        token = "delete-token-456"

        powerdns_provider.create_txt_record(domain, token)
        powerdns_provider.delete_txt_record(domain, token)

        # Verify record no longer exists
        headers = {"X-API-Key": powerdns_api_key}
        response = httpx.get(
            f"{powerdns_api_url}/api/v1/servers/localhost/zones/example.org.",
            headers=headers,
            timeout=30,
        )
        zone_data = response.json()

        txt_records = [
            rrset
            for rrset in zone_data.get("rrsets", [])
            if rrset["name"] == f"_acme-challenge.{domain}." and rrset["type"] == "TXT"
        ]
        assert len(txt_records) == 0
