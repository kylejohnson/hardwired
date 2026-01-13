"""DNS-01 challenge implementation."""

import base64
import hashlib


def compute_key_authorization(token: str, thumbprint: str) -> str:
    """Compute the key authorization string.

    The key authorization is the token concatenated with the account
    key thumbprint, separated by a period.

    Args:
        token: The challenge token from the ACME server.
        thumbprint: The base64url-encoded SHA-256 thumbprint of the account key.

    Returns:
        The key authorization string (token.thumbprint).
    """
    return f"{token}.{thumbprint}"


def compute_dns_txt_value(key_authorization: str) -> str:
    """Compute the DNS TXT record value for DNS-01 challenge.

    The TXT record value is the base64url-encoded SHA-256 digest
    of the key authorization string.

    Args:
        key_authorization: The key authorization string.

    Returns:
        The base64url-encoded SHA-256 digest (without padding).
    """
    digest = hashlib.sha256(key_authorization.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
