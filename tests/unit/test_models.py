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
        )

        assert result.private_key_pem is None


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
