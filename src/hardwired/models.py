"""Pydantic models for ACME protocol resources."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


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

    status: str
    contact: list[str] | None = None
    orders: str | None = None
    terms_of_service_agreed: bool | None = Field(default=None, alias="termsOfServiceAgreed")

    model_config = {"populate_by_name": True}


class Identifier(BaseModel):
    """ACME identifier (RFC 8555 Section 7.1.3)."""

    type: str
    value: str


class Challenge(BaseModel):
    """ACME challenge resource (RFC 8555 Section 7.5.1)."""

    type: str
    url: str
    status: str
    token: str
    validated: datetime | None = None
    error: dict[str, Any] | None = None


class Authorization(BaseModel):
    """ACME authorization resource (RFC 8555 Section 7.1.4)."""

    status: str
    identifier: Identifier
    challenges: list[Challenge]
    expires: datetime | None = None
    wildcard: bool | None = None


class Order(BaseModel):
    """ACME order resource (RFC 8555 Section 7.1.3)."""

    status: str
    identifiers: list[Identifier]
    authorizations: list[str]
    finalize: str
    expires: datetime | None = None
    not_before: datetime | None = Field(default=None, alias="notBefore")
    not_after: datetime | None = Field(default=None, alias="notAfter")
    certificate: str | None = None
    error: dict[str, Any] | None = None

    model_config = {"populate_by_name": True}


class CertificateResult(BaseModel):
    """Result of certificate issuance."""

    certificate_pem: str
    private_key_pem: str | None
    expires_at: datetime
