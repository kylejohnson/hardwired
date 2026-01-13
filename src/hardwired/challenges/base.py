"""Base class for challenge handlers."""

from abc import ABC, abstractmethod

from hardwired.models import Authorization, Challenge


class ChallengeHandler(ABC):
    """Abstract base class for ACME challenge handlers."""

    @abstractmethod
    def prepare(self, challenge: Challenge, authorization: Authorization) -> None:
        """Prepare for challenge validation.

        This method should set up whatever is needed for the ACME server
        to validate the challenge (e.g., DNS record, HTTP file).

        Args:
            challenge: The challenge to prepare for.
            authorization: The authorization containing the challenge.
        """
        ...

    @abstractmethod
    def cleanup(self, challenge: Challenge, authorization: Authorization) -> None:
        """Clean up after challenge validation.

        This method should remove any resources created during prepare().

        Args:
            challenge: The challenge to clean up.
            authorization: The authorization containing the challenge.
        """
        ...
