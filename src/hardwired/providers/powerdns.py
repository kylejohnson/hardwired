"""PowerDNS provider for ACME DNS-01 challenges."""

import httpx

from hardwired._logging import get_logger
from hardwired.providers.base import DnsProvider

logger = get_logger(__name__)


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
        to find the authoritative zone in PowerDNS by testing each
        candidate zone URL.

        Args:
            domain: The full domain name to find zone for.

        Returns:
            The zone name (with trailing dot).

        Raises:
            ValueError: If no matching zone is found.
        """
        headers = {"X-API-Key": self.api_key}

        # Normalize domain (ensure trailing dot for zone name)
        domain = domain.rstrip(".") + "."

        # Try each parent domain level
        parts = domain.rstrip(".").split(".")
        for i in range(len(parts)):
            candidate = ".".join(parts[i:]) + "."

            logger.debug(
                "Trying zone candidate",
                extra={"domain": domain, "candidate": candidate},
            )

            # Test if this zone exists by requesting it directly
            response = httpx.get(
                f"{self.api_url}/api/v1/servers/{self.server_id}/zones/{candidate}",
                headers=headers,
                timeout=self.timeout,
            )

            if response.status_code == 200:
                logger.debug(
                    "Zone found",
                    extra={"domain": domain, "zone": candidate},
                )
                return candidate

        raise ValueError(f"No zone found for domain: {domain}")

    def _handle_response(self, response: httpx.Response, zone: str) -> None:
        """Handle PowerDNS API response status codes.

        Args:
            response: The httpx Response object.
            zone: The zone name (for error messages).

        Raises:
            ValueError: For API errors with descriptive messages.
        """
        if response.status_code == 204:
            logger.debug(
                "PowerDNS API request successful",
                extra={"zone": zone, "status_code": response.status_code},
            )
            return  # Success

        # Try to extract error detail from response body
        try:
            error_data = response.json()
            detail = error_data.get("error", response.text)
        except Exception:
            detail = response.text or "Unknown error"

        status_messages = {
            400: f"Bad Request: {detail}",
            404: f"Zone not found: {detail}",
            422: f"Unprocessable Entity: {detail}",
            500: f"Server Error: {detail}",
        }

        message = status_messages.get(
            response.status_code,
            f"Unexpected error ({response.status_code}): {detail}",
        )
        logger.error(
            "PowerDNS API error",
            extra={"zone": zone, "status_code": response.status_code, "detail": detail},
        )
        raise ValueError(message)

    def _common_dns_record(self, domain: str, token: str, changetype: str) -> None:
        """Execute a DNS record change via PowerDNS API.

        Args:
            domain: The domain name (without _acme-challenge prefix).
            token: The challenge token value.
            changetype: PowerDNS changetype - "REPLACE" or "DELETE".

        Raises:
            ValueError: If changetype is invalid, zone not found, or API error.
        """
        if changetype not in ("REPLACE", "DELETE"):
            raise ValueError(f"Invalid changetype: {changetype}. Must be 'REPLACE' or 'DELETE'.")

        zone = self._find_zone(domain)
        record_name = f"_acme-challenge.{domain.rstrip('.')}."

        headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json",
        }

        rrset: dict = {
            "name": record_name,
            "type": "TXT",
            "changetype": changetype,
        }

        if changetype == "REPLACE":
            rrset["ttl"] = 60
            rrset["records"] = [{"content": f'"{token}"', "disabled": False}]

        payload = {"rrsets": [rrset]}

        response = httpx.patch(
            f"{self.api_url}/api/v1/servers/{self.server_id}/zones/{zone}",
            headers=headers,
            json=payload,
            timeout=self.timeout,
        )
        self._handle_response(response, zone)

    def create_txt_record(self, domain: str, token: str) -> None:
        """Create a TXT record via PowerDNS API.

        Args:
            domain: The domain name (without _acme-challenge prefix).
            token: The challenge token value.

        Raises:
            ValueError: If no matching zone is found or API error.
        """
        self._common_dns_record(domain, token, "REPLACE")
        logger.info(
            "TXT record created",
            extra={"domain": domain, "record_name": f"_acme-challenge.{domain}"},
        )

    def delete_txt_record(self, domain: str, token: str) -> None:
        """Delete a TXT record via PowerDNS API.

        Args:
            domain: The domain name (without _acme-challenge prefix).
            token: The challenge token value (unused, kept for interface).

        Raises:
            ValueError: If no matching zone is found or API error.
        """
        self._common_dns_record(domain, token, "DELETE")
        logger.info(
            "TXT record deleted",
            extra={"domain": domain, "record_name": f"_acme-challenge.{domain}"},
        )

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
