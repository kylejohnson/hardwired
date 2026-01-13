"""DNS providers for ACME challenge validation."""

from hardwired.providers.base import DnsProvider
from hardwired.providers.test import TestProvider

__all__ = ["DnsProvider", "TestProvider"]
