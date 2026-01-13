"""Unit tests for crypto module."""

import base64
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from hardwired.crypto import (
    create_csr,
    generate_ecdsa_key,
    generate_rsa_key,
    key_thumbprint,
    sign_jws,
)


class TestKeyGeneration:
    """Tests for key generation functions."""

    def test_generate_rsa_key_2048(self):
        """Generate RSA 2048-bit key."""
        key = generate_rsa_key(key_size=2048)
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 2048

    def test_generate_rsa_key_4096(self):
        """Generate RSA 4096-bit key."""
        key = generate_rsa_key(key_size=4096)
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 4096

    def test_generate_rsa_key_default_size(self):
        """Default RSA key size should be 2048."""
        key = generate_rsa_key()
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 2048

    def test_generate_ecdsa_key_p256(self):
        """Generate ECDSA P-256 key."""
        key = generate_ecdsa_key(curve="P-256")
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert key.curve.name == "secp256r1"

    def test_generate_ecdsa_key_p384(self):
        """Generate ECDSA P-384 key."""
        key = generate_ecdsa_key(curve="P-384")
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert key.curve.name == "secp384r1"

    def test_generate_ecdsa_key_default_curve(self):
        """Default ECDSA curve should be P-256."""
        key = generate_ecdsa_key()
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert key.curve.name == "secp256r1"

    def test_generate_ecdsa_key_invalid_curve(self):
        """Invalid curve should raise ValueError."""
        with pytest.raises(ValueError, match="Unsupported curve"):
            generate_ecdsa_key(curve="P-512")


class TestCSRCreation:
    """Tests for CSR creation."""

    def test_create_csr_single_domain(self):
        """Create CSR for single domain."""
        key = generate_rsa_key(2048)
        csr = create_csr(key, domains=["example.com"])

        assert csr.is_signature_valid
        # Check domain in SAN extension
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = [name.value for name in san.value]
        assert "example.com" in names

    def test_create_csr_san(self):
        """Create CSR with multiple domains (SAN)."""
        key = generate_rsa_key(2048)
        domains = ["example.com", "www.example.com", "api.example.com"]
        csr = create_csr(key, domains=domains)

        assert csr.is_signature_valid
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = [name.value for name in san.value]
        for domain in domains:
            assert domain in names

    def test_create_csr_wildcard(self):
        """Create CSR with wildcard domain."""
        key = generate_rsa_key(2048)
        csr = create_csr(key, domains=["*.example.com", "example.com"])

        assert csr.is_signature_valid
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = [name.value for name in san.value]
        assert "*.example.com" in names
        assert "example.com" in names

    def test_create_csr_with_ecdsa_key(self):
        """Create CSR with ECDSA key."""
        key = generate_ecdsa_key("P-256")
        csr = create_csr(key, domains=["example.com"])

        assert csr.is_signature_valid

    def test_create_csr_empty_domains_raises(self):
        """Empty domains list should raise ValueError."""
        key = generate_rsa_key(2048)
        with pytest.raises(ValueError, match="At least one domain"):
            create_csr(key, domains=[])


class TestJWSSigning:
    """Tests for JWS signing."""

    def test_jws_sign_rsa_structure(self):
        """JWS with RSA key has correct structure."""
        key = generate_rsa_key(2048)
        jws = sign_jws(
            key=key,
            payload={"test": "data"},
            url="https://example.com/acme",
            nonce="test-nonce-123",
        )

        # JWS is base64url encoded: header.payload.signature
        parts = jws.split(".")
        assert len(parts) == 3

        # Decode and verify header
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        assert header["alg"] == "RS256"
        assert header["nonce"] == "test-nonce-123"
        assert header["url"] == "https://example.com/acme"
        assert "jwk" in header  # JWK for new accounts

    def test_jws_sign_ecdsa_structure(self):
        """JWS with ECDSA key has correct structure."""
        key = generate_ecdsa_key("P-256")
        jws = sign_jws(
            key=key,
            payload={"test": "data"},
            url="https://example.com/acme",
            nonce="test-nonce-456",
        )

        parts = jws.split(".")
        assert len(parts) == 3

        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        assert header["alg"] == "ES256"
        assert header["nonce"] == "test-nonce-456"

    def test_jws_sign_with_kid(self):
        """JWS with kid (account URL) instead of jwk."""
        key = generate_rsa_key(2048)
        jws = sign_jws(
            key=key,
            payload={"test": "data"},
            url="https://example.com/acme",
            nonce="test-nonce",
            kid="https://example.com/acme/acct/123",
        )

        parts = jws.split(".")
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        assert header["kid"] == "https://example.com/acme/acct/123"
        assert "jwk" not in header  # kid and jwk are mutually exclusive

    def test_jws_sign_empty_payload(self):
        """JWS with empty payload (for POST-as-GET)."""
        key = generate_rsa_key(2048)
        jws = sign_jws(
            key=key,
            payload="",  # Empty string for POST-as-GET
            url="https://example.com/acme/order/123",
            nonce="test-nonce",
            kid="https://example.com/acme/acct/123",
        )

        parts = jws.split(".")
        assert len(parts) == 3
        # Empty payload should be empty string, not "{}"
        assert parts[1] == ""

    def test_jws_payload_is_base64url_encoded(self):
        """Payload should be base64url encoded JSON."""
        key = generate_rsa_key(2048)
        payload = {"resource": "new-acct", "contact": ["mailto:test@example.com"]}
        jws = sign_jws(
            key=key,
            payload=payload,
            url="https://example.com/acme",
            nonce="test-nonce",
        )

        parts = jws.split(".")
        decoded_payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        assert decoded_payload == payload


class TestKeyThumbprint:
    """Tests for key thumbprint computation."""

    def test_key_thumbprint_rsa(self):
        """Thumbprint for RSA key is base64url-encoded SHA-256."""
        key = generate_rsa_key(2048)
        thumbprint = key_thumbprint(key)

        # Thumbprint should be base64url encoded SHA-256 (32 bytes = 43 chars without padding)
        assert len(thumbprint) == 43
        # Should only contain base64url characters
        base64url_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        assert all(c in base64url_chars for c in thumbprint)

    def test_key_thumbprint_ecdsa(self):
        """Thumbprint for ECDSA key is base64url-encoded SHA-256."""
        key = generate_ecdsa_key("P-256")
        thumbprint = key_thumbprint(key)

        assert len(thumbprint) == 43
        base64url_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        assert all(c in base64url_chars for c in thumbprint)

    def test_key_thumbprint_deterministic(self):
        """Same key should always produce same thumbprint."""
        key = generate_rsa_key(2048)
        thumbprint1 = key_thumbprint(key)
        thumbprint2 = key_thumbprint(key)

        assert thumbprint1 == thumbprint2

    def test_key_thumbprint_different_keys(self):
        """Different keys should produce different thumbprints."""
        key1 = generate_rsa_key(2048)
        key2 = generate_rsa_key(2048)

        thumbprint1 = key_thumbprint(key1)
        thumbprint2 = key_thumbprint(key2)

        assert thumbprint1 != thumbprint2
