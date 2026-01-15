"""PowerDNS provider for ACME DNS-01 challenges."""

import httpx

from hardwired.providers.base import DnsProvider


class PowerDnsProvider(DnsProvider):
    """DNS provider for PowerDNS authoritative server.

    This provider manages TXT records for ACME DNS-01 challenges
    via the PowerDNS HTTP API.

    Args:
        api_url: Base URL of the PowerDNS API (e.g., "http://localhost:8081").
        api_key: API key for X-API-Key authentication header.
        server_id: PowerDNS server ID (default: "localhost").
        timeout: HTTP request timeout in seconds (default: 30).
    """

    def __init__(
        self,
        api_url: str,
        api_key: str,
        server_id: str = "localhost",
        timeout: int = 30,
    ):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.server_id = server_id
        self.timeout = timeout

    def _find_zone(self, domain: str) -> str:
        """Find the apex zone containing the given domain.

        Iterates through domain parts from most specific to least
        to find the authoritative zone in PowerDNS.

        Args:
            domain: The full domain name to find zone for.

        Returns:
            The zone name (with trailing dot).

        Raises:
            ValueError: If no matching zone is found.
        """
        headers = {"X-API-Key": self.api_key}

        response = httpx.get(
            f"{self.api_url}/api/v1/servers/{self.server_id}/zones",
            headers=headers,
            timeout=self.timeout,
        )
        response.raise_for_status()
        zones = {z["name"] for z in response.json()}

        # Normalize domain (ensure trailing dot)
        domain = domain.rstrip(".") + "."

        # Try each parent domain level
        parts = domain.rstrip(".").split(".")
        for i in range(len(parts)):
            candidate = ".".join(parts[i:]) + "."
            if candidate in zones:
                return candidate

        raise ValueError(f"No zone found for domain: {domain}")

    def create_txt_record(self, domain: str, token: str) -> None:
        """Create a TXT record via PowerDNS API.

        Args:
            domain: The domain name (without _acme-challenge prefix).
            token: The challenge token value.

        Raises:
            httpx.HTTPStatusError: If the API request fails.
            ValueError: If no matching zone is found.
        """
        zone = self._find_zone(domain)
        record_name = f"_acme-challenge.{domain.rstrip('.')}."

        headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json",
        }

        # PowerDNS requires TXT content to be quoted
        payload = {
            "rrsets": [
                {
                    "name": record_name,
                    "type": "TXT",
                    "ttl": 60,
                    "changetype": "REPLACE",
                    "records": [
                        {
                            "content": f'"{token}"',
                            "disabled": False,
                        }
                    ],
                }
            ]
        }

        response = httpx.patch(
            f"{self.api_url}/api/v1/servers/{self.server_id}/zones/{zone}",
            headers=headers,
            json=payload,
            timeout=self.timeout,
        )
        response.raise_for_status()

    def delete_txt_record(self, domain: str, token: str) -> None:
        """Delete a TXT record via PowerDNS API.

        Args:
            domain: The domain name (without _acme-challenge prefix).
            token: The challenge token value (unused, kept for interface).

        Raises:
            httpx.HTTPStatusError: If the API request fails.
            ValueError: If no matching zone is found.
        """
        zone = self._find_zone(domain)
        record_name = f"_acme-challenge.{domain.rstrip('.')}."

        headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json",
        }

        payload = {
            "rrsets": [
                {
                    "name": record_name,
                    "type": "TXT",
                    "changetype": "DELETE",
                }
            ]
        }

        response = httpx.patch(
            f"{self.api_url}/api/v1/servers/{self.server_id}/zones/{zone}",
            headers=headers,
            json=payload,
            timeout=self.timeout,
        )
        response.raise_for_status()

    def wait_for_propagation(self, domain: str, token: str, timeout: int = 120) -> bool:
        """Wait for DNS propagation.

        For PowerDNS, record updates are synchronous to the authoritative
        server. The API returns 204 on success, confirming the record is
        written. This method returns True immediately since there is no
        propagation delay within the PowerDNS server itself.

        Args:
            domain: The domain name.
            token: The expected token value.
            timeout: Maximum time to wait in seconds (unused).

        Returns:
            Always True (no propagation delay for authoritative server).
        """
        return True
