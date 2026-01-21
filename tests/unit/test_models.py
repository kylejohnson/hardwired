"""Unit tests for ACME models and exceptions."""

from datetime import UTC, datetime

from hardwired.exceptions import (
    AcmeError,
    AuthorizationError,
    ChallengeError,
    OrderError,
)
from hardwired.models import (
    Account,
    Authorization,
    AuthorizationInfo,
    CertificateResult,
    Challenge,
    Directory,
    Identifier,
    Order,
)


class TestDirectoryModel:
    """Tests for Directory model."""

    def test_directory_from_json(self):
        """Parse directory from JSON response."""
        data = {
            "newNonce": "https://example.com/acme/new-nonce",
            "newAccount": "https://example.com/acme/new-acct",
            "newOrder": "https://example.com/acme/new-order",
            "revokeCert": "https://example.com/acme/revoke-cert",
            "keyChange": "https://example.com/acme/key-change",
        }
        directory = Directory.model_validate(data)

        assert directory.new_nonce == "https://example.com/acme/new-nonce"
        assert directory.new_account == "https://example.com/acme/new-acct"
        assert directory.new_order == "https://example.com/acme/new-order"
        assert directory.revoke_cert == "https://example.com/acme/revoke-cert"
        assert directory.key_change == "https://example.com/acme/key-change"

    def test_directory_with_meta(self):
        """Parse directory with optional meta field."""
        data = {
            "newNonce": "https://example.com/acme/new-nonce",
            "newAccount": "https://example.com/acme/new-acct",
            "newOrder": "https://example.com/acme/new-order",
            "revokeCert": "https://example.com/acme/revoke-cert",
            "keyChange": "https://example.com/acme/key-change",
            "meta": {
                "termsOfService": "https://example.com/tos",
                "website": "https://example.com",
            },
        }
        directory = Directory.model_validate(data)

        assert directory.meta is not None
        assert directory.meta.get("termsOfService") == "https://example.com/tos"


class TestAccountModel:
    """Tests for Account model."""

    def test_account_from_json(self):
        """Parse account from JSON response."""
        data = {
            "status": "valid",
            "contact": ["mailto:admin@example.com"],
            "orders": "https://example.com/acme/orders/123",
        }
        account = Account.model_validate(data)

        assert account.status == "valid"
        assert account.contact == ["mailto:admin@example.com"]
        assert account.orders == "https://example.com/acme/orders/123"

    def test_account_minimal(self):
        """Parse account with minimal fields."""
        data = {
            "status": "valid",
        }
        account = Account.model_validate(data)

        assert account.status == "valid"
        assert account.contact is None
        assert account.orders is None


class TestIdentifierModel:
    """Tests for Identifier model."""

    def test_identifier_dns(self):
        """Parse DNS identifier."""
        data = {"type": "dns", "value": "example.com"}
        identifier = Identifier.model_validate(data)

        assert identifier.type == "dns"
        assert identifier.value == "example.com"


class TestOrderModel:
    """Tests for Order model."""

    def test_order_from_json(self):
        """Parse order from JSON response."""
        data = {
            "status": "pending",
            "expires": "2024-01-01T00:00:00Z",
            "identifiers": [{"type": "dns", "value": "example.com"}],
            "authorizations": ["https://example.com/acme/authz/123"],
            "finalize": "https://example.com/acme/order/123/finalize",
        }
        order = Order.model_validate(data)

        assert order.status == "pending"
        assert len(order.identifiers) == 1
        assert order.identifiers[0].value == "example.com"
        assert len(order.authorizations) == 1
        assert order.finalize == "https://example.com/acme/order/123/finalize"

    def test_order_with_certificate(self):
        """Parse order with certificate URL (ready/valid status)."""
        data = {
            "status": "valid",
            "identifiers": [{"type": "dns", "value": "example.com"}],
            "authorizations": ["https://example.com/acme/authz/123"],
            "finalize": "https://example.com/acme/order/123/finalize",
            "certificate": "https://example.com/acme/cert/456",
        }
        order = Order.model_validate(data)

        assert order.status == "valid"
        assert order.certificate == "https://example.com/acme/cert/456"

    def test_order_multiple_identifiers(self):
        """Parse order with multiple identifiers (SAN)."""
        data = {
            "status": "pending",
            "identifiers": [
                {"type": "dns", "value": "example.com"},
                {"type": "dns", "value": "www.example.com"},
                {"type": "dns", "value": "*.example.com"},
            ],
            "authorizations": [
                "https://example.com/acme/authz/1",
                "https://example.com/acme/authz/2",
                "https://example.com/acme/authz/3",
            ],
            "finalize": "https://example.com/acme/order/123/finalize",
        }
        order = Order.model_validate(data)

        assert len(order.identifiers) == 3
        assert len(order.authorizations) == 3


class TestChallengeModel:
    """Tests for Challenge model."""

    def test_challenge_dns01(self):
        """Parse DNS-01 challenge."""
        data = {
            "type": "dns-01",
            "url": "https://example.com/acme/chall/123",
            "status": "pending",
            "token": "abc123def456",
        }
        challenge = Challenge.model_validate(data)

        assert challenge.type == "dns-01"
        assert challenge.url == "https://example.com/acme/chall/123"
        assert challenge.status == "pending"
        assert challenge.token == "abc123def456"

    def test_challenge_valid_status(self):
        """Parse challenge with valid status."""
        data = {
            "type": "dns-01",
            "url": "https://example.com/acme/chall/123",
            "status": "valid",
            "token": "abc123",
            "validated": "2024-01-01T12:00:00Z",
        }
        challenge = Challenge.model_validate(data)

        assert challenge.status == "valid"
        assert challenge.validated is not None

    def test_challenge_with_error(self):
        """Parse challenge with error."""
        data = {
            "type": "dns-01",
            "url": "https://example.com/acme/chall/123",
            "status": "invalid",
            "token": "abc123",
            "error": {
                "type": "urn:ietf:params:acme:error:dns",
                "detail": "DNS lookup failed",
            },
        }
        challenge = Challenge.model_validate(data)

        assert challenge.status == "invalid"
        assert challenge.error is not None
        assert challenge.error["type"] == "urn:ietf:params:acme:error:dns"


class TestAuthorizationModel:
    """Tests for Authorization model."""

    def test_authorization_from_json(self):
        """Parse authorization from JSON response."""
        data = {
            "status": "pending",
            "identifier": {"type": "dns", "value": "example.com"},
            "challenges": [
                {
                    "type": "dns-01",
                    "url": "https://example.com/acme/chall/dns",
                    "status": "pending",
                    "token": "dns-token",
                },
                {
                    "type": "http-01",
                    "url": "https://example.com/acme/chall/http",
                    "status": "pending",
                    "token": "http-token",
                },
            ],
        }
        authz = Authorization.model_validate(data)

        assert authz.status == "pending"
        assert authz.identifier.value == "example.com"
        assert len(authz.challenges) == 2
        assert authz.challenges[0].type == "dns-01"

    def test_authorization_wildcard(self):
        """Parse authorization for wildcard domain."""
        data = {
            "status": "pending",
            "identifier": {"type": "dns", "value": "example.com"},
            "wildcard": True,
            "challenges": [
                {
                    "type": "dns-01",
                    "url": "https://example.com/acme/chall/123",
                    "status": "pending",
                    "token": "abc123",
                },
            ],
        }
        authz = Authorization.model_validate(data)

        assert authz.wildcard is True


class TestAuthorizationInfoModel:
    """Tests for AuthorizationInfo model."""

    def test_authorization_info_model(self):
        """AuthorizationInfo should have url, domain, and expires_at."""
        info = AuthorizationInfo(
            url="https://acme.example/authz/123",
            domain="example.com",
            expires_at=datetime(2026, 2, 1, tzinfo=UTC),
        )
        assert info.url == "https://acme.example/authz/123"
        assert info.domain == "example.com"
        assert info.expires_at.year == 2026

    def test_authorization_info_wildcard_domain(self):
        """AuthorizationInfo should work with base domain for wildcards."""
        info = AuthorizationInfo(
            url="https://acme.example/authz/456",
            domain="example.com",  # Base domain, covers *.example.com
            expires_at=datetime(2026, 2, 15, tzinfo=UTC),
        )
        assert info.domain == "example.com"


class TestCertificateResultModel:
    """Tests for CertificateResult model."""

    def test_certificate_result(self):
        """Create certificate result."""
        cert_pem = "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
        key_pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
        result = CertificateResult(
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
            expires_at=datetime(2024, 12, 31, 23, 59, 59, tzinfo=UTC),
            domains=["example.com"],
            authorizations=[],
        )

        assert "CERTIFICATE" in result.certificate_pem
        assert result.private_key_pem is not None
        assert "PRIVATE KEY" in result.private_key_pem
        assert result.expires_at.year == 2024

    def test_certificate_result_no_private_key(self):
        """Certificate result without private key (user provided CSR)."""
        result = CertificateResult(
            certificate_pem="-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
            private_key_pem=None,
            expires_at=datetime(2024, 12, 31, 23, 59, 59, tzinfo=UTC),
            domains=[],
            authorizations=[],
        )

        assert result.private_key_pem is None

    def test_certificate_result_includes_domains(self):
        """CertificateResult should include domains list."""
        result = CertificateResult(
            certificate_pem="-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
            private_key_pem="-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
            expires_at=datetime(2026, 3, 1, tzinfo=UTC),
            domains=["example.com", "*.example.com"],
            authorizations=[],
        )
        assert result.domains == ["example.com", "*.example.com"]
        assert len(result.domains) == 2

    def test_certificate_result_includes_authorization_info(self):
        """CertificateResult should include authorization info for deactivation."""
        authz_info = AuthorizationInfo(
            url="https://acme.example/authz/789",
            domain="example.com",
            expires_at=datetime(2026, 2, 15, tzinfo=UTC),
        )
        result = CertificateResult(
            certificate_pem="-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
            private_key_pem="-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
            expires_at=datetime(2026, 3, 1, tzinfo=UTC),
            domains=["example.com", "*.example.com"],
            authorizations=[authz_info],
        )
        assert len(result.authorizations) == 1
        assert result.authorizations[0].domain == "example.com"
        assert result.authorizations[0].url == "https://acme.example/authz/789"


class TestAcmeError:
    """Tests for ACME error parsing."""

    def test_acme_error_from_response(self):
        """Parse ACME error from response."""
        error_response = {
            "type": "urn:ietf:params:acme:error:malformed",
            "detail": "Request payload did not parse as JSON",
            "status": 400,
        }
        error = AcmeError.from_response(error_response, status_code=400)

        assert error.type == "urn:ietf:params:acme:error:malformed"
        assert error.detail == "Request payload did not parse as JSON"
        assert error.status_code == 400
        assert "malformed" in str(error)

    def test_acme_error_unauthorized(self):
        """Parse unauthorized error."""
        error_response = {
            "type": "urn:ietf:params:acme:error:unauthorized",
            "detail": "Account key does not match",
        }
        error = AcmeError.from_response(error_response, status_code=403)

        assert error.type == "urn:ietf:params:acme:error:unauthorized"
        assert error.status_code == 403

    def test_acme_error_with_subproblems(self):
        """Parse error with subproblems."""
        error_response = {
            "type": "urn:ietf:params:acme:error:compound",
            "detail": "Multiple problems",
            "subproblems": [
                {
                    "type": "urn:ietf:params:acme:error:dns",
                    "detail": "DNS lookup failed for example.com",
                    "identifier": {"type": "dns", "value": "example.com"},
                },
            ],
        }
        error = AcmeError.from_response(error_response, status_code=400)

        assert error.subproblems is not None
        assert len(error.subproblems) == 1


class TestChallengeError:
    """Tests for ChallengeError exception."""

    def test_challenge_error_is_acme_error(self):
        """ChallengeError should be subclass of AcmeError."""
        error = ChallengeError(
            type="urn:ietf:params:acme:error:dns",
            detail="DNS validation failed",
            status_code=400,
        )

        assert isinstance(error, AcmeError)
        assert isinstance(error, ChallengeError)


class TestOrderError:
    """Tests for OrderError exception."""

    def test_order_error_is_acme_error(self):
        """OrderError should be subclass of AcmeError."""
        error = OrderError(
            type="urn:ietf:params:acme:error:orderNotReady",
            detail="Order is not ready for finalization",
            status_code=403,
        )

        assert isinstance(error, AcmeError)
        assert isinstance(error, OrderError)


class TestAuthorizationError:
    """Tests for AuthorizationError exception."""

    def test_authorization_error_is_acme_error(self):
        """AuthorizationError should be subclass of AcmeError."""
        error = AuthorizationError(
            type="urn:ietf:params:acme:error:unauthorized",
            detail="Authorization expired",
            status_code=403,
        )

        assert isinstance(error, AcmeError)
        assert isinstance(error, AuthorizationError)


# ============================================================================
# New tests for enhanced ACME error handling with Retry-After support
# ============================================================================

from hardwired.exceptions import (
    BadNonceError,
    CAAError,
    DnsValidationError,
    RateLimitError,
    ServerInternalError,
)


class TestRetryAfterParsing:
    """Tests for Retry-After header parsing."""

    def test_parse_retry_after_seconds(self):
        """Parse Retry-After as integer seconds."""
        result = AcmeError._parse_retry_after("120")
        assert result == 120

    def test_parse_retry_after_http_date(self):
        """Parse Retry-After as HTTP-date."""
        from datetime import datetime, timedelta, timezone
        from email.utils import format_datetime

        future = datetime.now(timezone.utc) + timedelta(hours=1)
        http_date = format_datetime(future, usegmt=True)
        result = AcmeError._parse_retry_after(http_date)
        assert 3500 < result < 3700  # ~1 hour

    def test_parse_retry_after_none(self):
        """Return None for missing header."""
        result = AcmeError._parse_retry_after(None)
        assert result is None

    def test_parse_retry_after_invalid(self):
        """Return None for invalid value."""
        result = AcmeError._parse_retry_after("invalid")
        assert result is None


class TestAcmeErrorWithHeaders:
    """Tests for AcmeError with header support."""

    def test_from_response_with_retry_after(self):
        """Create error with Retry-After header."""
        error_response = {
            "type": "urn:ietf:params:acme:error:rateLimited",
            "detail": "too many requests",
        }
        headers = {"Retry-After": "3600"}
        error = AcmeError.from_response(error_response, 429, headers)

        assert error.retry_after == 3600

    def test_get_retry_seconds_with_value(self):
        """get_retry_seconds returns retry_after when set."""
        error = AcmeError(
            type="test", detail="test", status_code=429, retry_after=1800
        )
        assert error.get_retry_seconds(default=3600) == 1800

    def test_get_retry_seconds_default(self):
        """get_retry_seconds returns default when retry_after is None."""
        error = AcmeError(
            type="test", detail="test", status_code=429, retry_after=None
        )
        assert error.get_retry_seconds(default=3600) == 3600


class TestRateLimitError:
    """Tests for RateLimitError exception."""

    def test_rate_limit_error_is_acme_error(self):
        """RateLimitError should be subclass of AcmeError."""
        error = RateLimitError(
            type="urn:ietf:params:acme:error:rateLimited",
            detail="too many certificates",
            status_code=429,
        )
        assert isinstance(error, AcmeError)
        assert isinstance(error, RateLimitError)

    def test_rate_limit_type_duplicate_certificate(self):
        """Detect duplicate certificate rate limit."""
        error = RateLimitError(
            type="urn:ietf:params:acme:error:rateLimited",
            detail="too many certificates (5) already issued for this exact set of domains",
            status_code=429,
        )
        assert error.rate_limit_type == "duplicate_certificate"

    def test_rate_limit_type_per_domain(self):
        """Detect per-domain rate limit."""
        error = RateLimitError(
            type="urn:ietf:params:acme:error:rateLimited",
            detail="too many certificates already issued for example.com",
            status_code=429,
        )
        assert error.rate_limit_type == "certificates_per_domain"

    def test_rate_limit_type_orders(self):
        """Detect orders per account rate limit."""
        error = RateLimitError(
            type="urn:ietf:params:acme:error:rateLimited",
            detail="too many new orders recently",
            status_code=429,
        )
        assert error.rate_limit_type == "orders_per_account"

    def test_from_response_creates_rate_limit_error(self):
        """from_response routes rateLimited to RateLimitError."""
        error_response = {
            "type": "urn:ietf:params:acme:error:rateLimited",
            "detail": "too many requests",
        }
        error = AcmeError.from_response(error_response, 429)
        assert isinstance(error, RateLimitError)


class TestDnsValidationError:
    """Tests for DnsValidationError exception."""

    def test_dns_validation_error_is_acme_error(self):
        """DnsValidationError should be subclass of AcmeError."""
        error = DnsValidationError(
            type="urn:ietf:params:acme:error:dns",
            detail="DNS problem",
            status_code=400,
        )
        assert isinstance(error, AcmeError)

    def test_from_response_creates_dns_error(self):
        """from_response routes dns error to DnsValidationError."""
        error_response = {
            "type": "urn:ietf:params:acme:error:dns",
            "detail": "DNS problem",
        }
        error = AcmeError.from_response(error_response, 400)
        assert isinstance(error, DnsValidationError)


class TestCAAError:
    """Tests for CAAError exception."""

    def test_caa_error_is_acme_error(self):
        """CAAError should be subclass of AcmeError."""
        error = CAAError(
            type="urn:ietf:params:acme:error:caa",
            detail="CAA record forbids",
            status_code=403,
        )
        assert isinstance(error, AcmeError)

    def test_from_response_creates_caa_error(self):
        """from_response routes caa error to CAAError."""
        error_response = {
            "type": "urn:ietf:params:acme:error:caa",
            "detail": "CAA record forbids",
        }
        error = AcmeError.from_response(error_response, 403)
        assert isinstance(error, CAAError)


class TestServerInternalError:
    """Tests for ServerInternalError exception."""

    def test_server_internal_error_is_acme_error(self):
        """ServerInternalError should be subclass of AcmeError."""
        error = ServerInternalError(
            type="urn:ietf:params:acme:error:serverInternal",
            detail="Internal error",
            status_code=500,
        )
        assert isinstance(error, AcmeError)

    def test_from_response_creates_server_internal_error(self):
        """from_response routes serverInternal to ServerInternalError."""
        error_response = {
            "type": "urn:ietf:params:acme:error:serverInternal",
            "detail": "Internal error",
        }
        error = AcmeError.from_response(error_response, 500)
        assert isinstance(error, ServerInternalError)


class TestBadNonceError:
    """Tests for BadNonceError exception."""

    def test_bad_nonce_error_is_acme_error(self):
        """BadNonceError should be subclass of AcmeError."""
        error = BadNonceError(
            type="urn:ietf:params:acme:error:badNonce",
            detail="Bad nonce",
            status_code=400,
        )
        assert isinstance(error, AcmeError)

    def test_from_response_creates_bad_nonce_error(self):
        """from_response routes badNonce to BadNonceError."""
        error_response = {
            "type": "urn:ietf:params:acme:error:badNonce",
            "detail": "Bad nonce",
        }
        error = AcmeError.from_response(error_response, 400)
        assert isinstance(error, BadNonceError)
