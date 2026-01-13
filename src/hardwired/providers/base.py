"""Abstract base class for DNS providers."""

from abc import ABC, abstractmethod


class DnsProvider(ABC):
    """Abstract interface for DNS providers.

    DNS providers are responsible for creating and deleting TXT records
    used for ACME DNS-01 challenge validation.
    """

    @abstractmethod
    def create_txt_record(self, domain: str, token: str) -> None:
        """Create a TXT record for ACME challenge.

        Creates a TXT record at _acme-challenge.{domain} with the
        provided token value.

        Args:
            domain: The domain name (without _acme-challenge prefix).
            token: The challenge token value to set as TXT record.

        Raises:
            Exception: If record creation fails.
        """
        ...

    @abstractmethod
    def delete_txt_record(self, domain: str, token: str) -> None:
        """Delete a TXT record for ACME challenge.

        Removes the TXT record at _acme-challenge.{domain}.

        Args:
            domain: The domain name (without _acme-challenge prefix).
            token: The challenge token value (for providers that need it).

        Raises:
            Exception: If record deletion fails.
        """
        ...

    @abstractmethod
    def wait_for_propagation(self, domain: str, token: str, timeout: int = 120) -> bool:
        """Wait for DNS propagation.

        Waits until the TXT record is visible via DNS queries.

        Args:
            domain: The domain name.
            token: The expected token value.
            timeout: Maximum time to wait in seconds.

        Returns:
            True if the record propagated successfully, False if timeout.
        """
        ...
