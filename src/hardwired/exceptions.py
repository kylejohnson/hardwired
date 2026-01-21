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
        retry_after: int | None = None,
    ):
        self.type = type
        self.detail = detail
        self.status_code = status_code
        self.subproblems = subproblems
        self.retry_after = retry_after
        super().__init__(f"{type}: {detail}")

    @classmethod
    def from_response(
        cls,
        data: dict[str, Any],
        status_code: int,
        headers: dict[str, str] | None = None,
    ) -> "AcmeError":
        """Create an AcmeError from a JSON response.

        Routes to appropriate subclass based on error type.

        Args:
            data: Parsed JSON error response.
            status_code: HTTP status code.
            headers: Response headers (for Retry-After extraction).

        Returns:
            AcmeError instance (or appropriate subclass).
        """
        retry_after = cls._parse_retry_after(headers.get("Retry-After")) if headers else None
        error_type = data.get("type", "unknown")

        kwargs: dict[str, Any] = {
            "type": error_type,
            "detail": data.get("detail", "Unknown error"),
            "status_code": status_code,
            "subproblems": data.get("subproblems"),
            "retry_after": retry_after,
        }

        # Route to subclass based on error type
        if error_type == "urn:ietf:params:acme:error:rateLimited":
            return RateLimitError(**kwargs)
        elif error_type == "urn:ietf:params:acme:error:dns":
            return DnsValidationError(**kwargs)
        elif error_type == "urn:ietf:params:acme:error:caa":
            return CAAError(**kwargs)
        elif error_type == "urn:ietf:params:acme:error:serverInternal":
            return ServerInternalError(**kwargs)
        elif error_type == "urn:ietf:params:acme:error:badNonce":
            return BadNonceError(**kwargs)

        return cls(**kwargs)

    @staticmethod
    def _parse_retry_after(value: str | None) -> int | None:
        """Parse Retry-After header (seconds or HTTP-date).

        Args:
            value: Retry-After header value.

        Returns:
            Seconds to wait, or None if not parseable.
        """
        if not value:
            return None
        try:
            return int(value)
        except ValueError:
            from datetime import datetime, timezone
            from email.utils import parsedate_to_datetime

            try:
                dt = parsedate_to_datetime(value)
                return max(0, int((dt - datetime.now(timezone.utc)).total_seconds()))
            except Exception:
                return None

    def get_retry_seconds(self, default: int = 3600) -> int:
        """Get retry delay, falling back to default.

        Args:
            default: Default seconds if retry_after is not set.

        Returns:
            Number of seconds to wait before retrying.
        """
        return self.retry_after if self.retry_after is not None else default


class ChallengeError(AcmeError):
    """Error during challenge validation."""

    pass


class OrderError(AcmeError):
    """Error with order processing."""

    pass


class AuthorizationError(AcmeError):
    """Error with authorization processing."""

    pass


class RateLimitError(AcmeError):
    """Rate limit exceeded (urn:ietf:params:acme:error:rateLimited)."""

    @property
    def rate_limit_type(self) -> str:
        """Parse specific rate limit type from detail message.

        Returns:
            Rate limit type identifier.
        """
        detail = self.detail.lower()
        if "exact set" in detail:
            return "duplicate_certificate"  # 5/week, NOT overridable
        elif "too many certificates" in detail:
            return "certificates_per_domain"  # 50/week
        elif "too many new orders" in detail:
            return "orders_per_account"  # 300/3hr
        elif "failed authorizations" in detail:
            return "failed_authorizations"
        return "unknown"


class DnsValidationError(AcmeError):
    """DNS validation failed (urn:ietf:params:acme:error:dns)."""

    pass


class CAAError(AcmeError):
    """CAA record forbids issuance (urn:ietf:params:acme:error:caa)."""

    pass


class ServerInternalError(AcmeError):
    """ACME server internal error (urn:ietf:params:acme:error:serverInternal)."""

    pass


class BadNonceError(AcmeError):
    """Bad nonce error (urn:ietf:params:acme:error:badNonce)."""

    pass
