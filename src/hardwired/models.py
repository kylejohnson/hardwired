"""Pydantic models for ACME protocol resources."""

from datetime import datetime
from enum import IntEnum, StrEnum
from typing import Any

from pydantic import BaseModel, Field

# =============================================================================
# ACME Protocol Enums (RFC 8555)
# =============================================================================


class RevocationReason(IntEnum):
    """Certificate revocation reasons (RFC 5280 Section 5.3.1)."""

    UNSPECIFIED = 0
    KEY_COMPROMISE = 1
    CA_COMPROMISE = 2
    AFFILIATION_CHANGED = 3
    SUPERSEDED = 4
    CESSATION_OF_OPERATION = 5
    CERTIFICATE_HOLD = 6


class AcmeErrorType(StrEnum):
    """ACME error types (RFC 8555 Section 6.7)."""

    ACCOUNT_DOES_NOT_EXIST = "urn:ietf:params:acme:error:accountDoesNotExist"
    ALREADY_REVOKED = "urn:ietf:params:acme:error:alreadyRevoked"
    BAD_CSR = "urn:ietf:params:acme:error:badCSR"
    BAD_NONCE = "urn:ietf:params:acme:error:badNonce"
    BAD_PUBLIC_KEY = "urn:ietf:params:acme:error:badPublicKey"
    BAD_REVOCATION_REASON = "urn:ietf:params:acme:error:badRevocationReason"
    BAD_SIGNATURE_ALGORITHM = "urn:ietf:params:acme:error:badSignatureAlgorithm"
    CAA = "urn:ietf:params:acme:error:caa"
    COMPOUND = "urn:ietf:params:acme:error:compound"
    CONNECTION = "urn:ietf:params:acme:error:connection"
    DNS = "urn:ietf:params:acme:error:dns"
    EXTERNAL_ACCOUNT_REQUIRED = "urn:ietf:params:acme:error:externalAccountRequired"
    INCORRECT_RESPONSE = "urn:ietf:params:acme:error:incorrectResponse"
    INVALID_CONTACT = "urn:ietf:params:acme:error:invalidContact"
    MALFORMED = "urn:ietf:params:acme:error:malformed"
    ORDER_NOT_READY = "urn:ietf:params:acme:error:orderNotReady"
    RATE_LIMITED = "urn:ietf:params:acme:error:rateLimited"
    REJECTED_IDENTIFIER = "urn:ietf:params:acme:error:rejectedIdentifier"
    SERVER_INTERNAL = "urn:ietf:params:acme:error:serverInternal"
    TLS = "urn:ietf:params:acme:error:tls"
    UNAUTHORIZED = "urn:ietf:params:acme:error:unauthorized"
    UNSUPPORTED_CONTACT = "urn:ietf:params:acme:error:unsupportedContact"
    UNSUPPORTED_IDENTIFIER = "urn:ietf:params:acme:error:unsupportedIdentifier"
    USER_ACTION_REQUIRED = "urn:ietf:params:acme:error:userActionRequired"


class ChallengeStatus(StrEnum):
    """Challenge statuses (RFC 8555 Section 7.1.6)."""

    PENDING = "pending"
    PROCESSING = "processing"
    VALID = "valid"
    INVALID = "invalid"


class AuthorizationStatus(StrEnum):
    """Authorization statuses (RFC 8555 Section 7.1.6)."""

    PENDING = "pending"
    VALID = "valid"
    INVALID = "invalid"
    DEACTIVATED = "deactivated"
    EXPIRED = "expired"
    REVOKED = "revoked"


class OrderStatus(StrEnum):
    """Order statuses (RFC 8555 Section 7.1.6)."""

    PENDING = "pending"
    READY = "ready"
    PROCESSING = "processing"
    VALID = "valid"
    INVALID = "invalid"


class AccountStatus(StrEnum):
    """Account statuses (RFC 8555 Section 7.1.6)."""

    VALID = "valid"
    DEACTIVATED = "deactivated"
    REVOKED = "revoked"


class ChallengeType(StrEnum):
    """Challenge types (RFC 8555 Section 8)."""

    HTTP_01 = "http-01"
    DNS_01 = "dns-01"
    TLS_ALPN_01 = "tls-alpn-01"
    DNS_ACCOUNT_01 = "dns-account-01"


class IdentifierType(StrEnum):
    """Identifier types (RFC 8555 Section 9.7.7)."""

    DNS = "dns"


# =============================================================================
# Pydantic Models
# =============================================================================


class Directory(BaseModel):
    """ACME directory resource (RFC 8555 Section 7.1.1)."""

    new_nonce: str = Field(alias="newNonce")
    new_account: str = Field(alias="newAccount")
    new_order: str = Field(alias="newOrder")
    revoke_cert: str = Field(alias="revokeCert")
    key_change: str = Field(alias="keyChange")
    meta: dict[str, Any] | None = None

    model_config = {"populate_by_name": True}


class Account(BaseModel):
    """ACME account resource (RFC 8555 Section 7.1.2)."""

    status: AccountStatus
    contact: list[str] | None = None
    orders: str | None = None
    terms_of_service_agreed: bool | None = Field(default=None, alias="termsOfServiceAgreed")

    model_config = {"populate_by_name": True}


class Identifier(BaseModel):
    """ACME identifier (RFC 8555 Section 7.1.3)."""

    type: IdentifierType
    value: str


class Challenge(BaseModel):
    """ACME challenge resource (RFC 8555 Section 7.5.1)."""

    type: ChallengeType
    url: str
    status: ChallengeStatus
    token: str
    validated: datetime | None = None
    error: dict[str, Any] | None = None


class Authorization(BaseModel):
    """ACME authorization resource (RFC 8555 Section 7.1.4)."""

    status: AuthorizationStatus
    identifier: Identifier
    challenges: list[Challenge]
    expires: datetime | None = None
    wildcard: bool | None = None


class Order(BaseModel):
    """ACME order resource (RFC 8555 Section 7.1.3)."""

    status: OrderStatus
    identifiers: list[Identifier]
    authorizations: list[str]
    finalize: str
    expires: datetime | None = None
    not_before: datetime | None = Field(default=None, alias="notBefore")
    not_after: datetime | None = Field(default=None, alias="notAfter")
    certificate: str | None = None
    error: dict[str, Any] | None = None

    model_config = {"populate_by_name": True}


class AuthorizationInfo(BaseModel):
    """Authorization details for deactivation support."""

    url: str
    domain: str
    expires_at: datetime


class CertificateResult(BaseModel):
    """Result of certificate issuance."""

    certificate_pem: str
    private_key_pem: str | None
    expires_at: datetime
    domains: list[str]
    authorizations: list[AuthorizationInfo]
