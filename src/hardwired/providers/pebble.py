"""Pebble DNS provider for pebble-challtestsrv."""

import httpx

from hardwired.providers.base import DnsProvider


class PebbleProvider(DnsProvider):
    """DNS provider for pebble-challtestsrv.

    This provider is used for testing against the Pebble ACME server
    and its associated challenge test server. It communicates with
    pebble-challtestsrv to set up DNS records that Pebble will query
    during challenge validation.

    Args:
        challtestsrv_url: Base URL of the pebble-challtestsrv management API.
    """

    def __init__(self, challtestsrv_url: str):
        self.challtestsrv_url = challtestsrv_url

    def create_txt_record(self, domain: str, token: str) -> None:
        """Create a TXT record via pebble-challtestsrv API.

        Args:
            domain: The domain name (without _acme-challenge prefix).
            token: The challenge token value.
        """
        # Format the ACME challenge hostname
        host = f"_acme-challenge.{domain}."

        response = httpx.post(
            f"{self.challtestsrv_url}/set-txt",
            json={
                "host": host,
                "value": token,
            },
        )
        response.raise_for_status()

    def delete_txt_record(self, domain: str, token: str) -> None:
        """Delete a TXT record via pebble-challtestsrv API.

        Args:
            domain: The domain name (without _acme-challenge prefix).
            token: The challenge token value (unused, but kept for interface).
        """
        host = f"_acme-challenge.{domain}."

        response = httpx.post(
            f"{self.challtestsrv_url}/clear-txt",
            json={
                "host": host,
            },
        )
        response.raise_for_status()

    def wait_for_propagation(self, domain: str, token: str, timeout: int = 120) -> bool:
        """Wait for DNS propagation.

        For the test provider, propagation is immediate since
        pebble-challtestsrv directly serves DNS responses.

        Returns:
            Always True (no actual propagation delay).
        """
        return True
