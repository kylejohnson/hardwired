"""Unit tests for challenge handling."""

import base64
import hashlib

from hardwired.challenges.dns01 import compute_dns_txt_value, compute_key_authorization


class TestKeyAuthorization:
    """Tests for key authorization computation."""

    def test_compute_key_authorization(self):
        """Key authorization is token.thumbprint."""
        token = "abc123"
        thumbprint = "xyz789"

        keyauth = compute_key_authorization(token, thumbprint)

        assert keyauth == "abc123.xyz789"

    def test_compute_key_authorization_with_special_chars(self):
        """Key authorization handles special characters in token."""
        token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"
        thumbprint = "yB_0xL-h7D4c5VZ3qG0UPIK8hEtD4gPVKg6eT7N8Ghk"

        keyauth = compute_key_authorization(token, thumbprint)

        assert keyauth == f"{token}.{thumbprint}"


class TestDnsTxtValue:
    """Tests for DNS TXT record value computation."""

    def test_compute_dns_txt_value(self):
        """TXT value is base64url(sha256(keyauth))."""
        keyauth = "test-key-authorization"

        txt_value = compute_dns_txt_value(keyauth)

        # Verify manually
        expected = (
            base64.urlsafe_b64encode(hashlib.sha256(keyauth.encode()).digest())
            .rstrip(b"=")
            .decode()
        )

        assert txt_value == expected

    def test_compute_dns_txt_value_length(self):
        """TXT value should be 43 characters (256 bits base64url without padding)."""
        keyauth = "any-key-authorization-string"

        txt_value = compute_dns_txt_value(keyauth)

        # SHA-256 is 32 bytes, base64url without padding is 43 chars
        assert len(txt_value) == 43

    def test_compute_dns_txt_value_no_padding(self):
        """TXT value should not have base64 padding."""
        keyauth = "test"

        txt_value = compute_dns_txt_value(keyauth)

        assert "=" not in txt_value
