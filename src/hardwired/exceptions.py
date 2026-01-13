"""ACME protocol exceptions."""

from typing import Any


class AcmeError(Exception):
    """Base exception for ACME protocol errors.

    Represents errors returned by the ACME server in the standard
    problem document format (RFC 7807).
    """

    def __init__(
        self,
        type: str,
        detail: str,
        status_code: int,
        subproblems: list[dict[str, Any]] | None = None,
    ):
        self.type = type
        self.detail = detail
        self.status_code = status_code
        self.subproblems = subproblems
        super().__init__(f"{type}: {detail}")

    @classmethod
    def from_response(cls, data: dict[str, Any], status_code: int) -> "AcmeError":
        """Create an AcmeError from a JSON response.

        Args:
            data: Parsed JSON error response.
            status_code: HTTP status code.

        Returns:
            AcmeError instance.
        """
        return cls(
            type=data.get("type", "unknown"),
            detail=data.get("detail", "Unknown error"),
            status_code=status_code,
            subproblems=data.get("subproblems"),
        )


class ChallengeError(AcmeError):
    """Error during challenge validation."""

    pass


class OrderError(AcmeError):
    """Error with order processing."""

    pass


class AuthorizationError(AcmeError):
    """Error with authorization processing."""

    pass
