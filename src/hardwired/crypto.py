"""Cryptographic utilities for ACME protocol operations."""

import base64
import hashlib
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

# Type alias for private keys
PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey


def generate_rsa_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """Generate an RSA private key.

    Args:
        key_size: Key size in bits (2048 or 4096 recommended).

    Returns:
        RSA private key.
    """
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )


def generate_ecdsa_key(curve: str = "P-256") -> ec.EllipticCurvePrivateKey:
    """Generate an ECDSA private key.

    Args:
        curve: Curve name ("P-256" or "P-384").

    Returns:
        ECDSA private key.

    Raises:
        ValueError: If curve is not supported.
    """
    curves = {
        "P-256": ec.SECP256R1(),
        "P-384": ec.SECP384R1(),
    }
    if curve not in curves:
        raise ValueError(f"Unsupported curve: {curve}. Supported: {list(curves.keys())}")

    return ec.generate_private_key(curves[curve])


def load_private_key_pem(pem_data: str, password: bytes | None = None) -> PrivateKey:
    """Load a private key from PEM-encoded data.

    Args:
        pem_data: PEM-encoded private key string.
        password: Optional password for encrypted keys.

    Returns:
        RSA or ECDSA private key.

    Raises:
        ValueError: If PEM data is invalid or password is incorrect.
    """
    try:
        key = serialization.load_pem_private_key(
            pem_data.encode("utf-8"),
            password=password,
        )
    except ValueError as e:
        error_msg = str(e).lower()
        if "password" in error_msg or "decrypt" in error_msg or "asn.1" in error_msg:
            raise ValueError("Invalid password or encrypted key requires password") from e
        raise ValueError(f"Invalid PEM data: {e}") from e
    except TypeError as e:
        # TypeError is raised when encrypted key is loaded without password
        raise ValueError("Invalid password or encrypted key requires password") from e

    if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise ValueError(f"Unsupported key type: {type(key).__name__}")

    return key


def create_csr(
    key: PrivateKey,
    domains: list[str],
) -> x509.CertificateSigningRequest:
    """Create a Certificate Signing Request (CSR).

    Args:
        key: Private key to sign the CSR.
        domains: List of domain names to include in the CSR.

    Returns:
        Certificate Signing Request.

    Raises:
        ValueError: If domains list is empty.
    """
    if not domains:
        raise ValueError("At least one domain is required")

    # Use first domain as Common Name
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
        ]
    )

    # Build SAN extension with all domains
    san = x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains])

    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(san, critical=False)
    )

    # Sign with appropriate algorithm
    if isinstance(key, rsa.RSAPrivateKey):
        return builder.sign(key, hashes.SHA256())
    else:
        return builder.sign(key, hashes.SHA256())


def _base64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def base64url_encode(data: bytes) -> str:
    """Base64url encode without padding (public API)."""
    return _base64url_encode(data)


def pem_to_der(pem: str) -> bytes:
    """Convert PEM-encoded certificate to DER format.

    Args:
        pem: PEM-encoded certificate string.

    Returns:
        DER-encoded certificate bytes.
    """
    cert = x509.load_pem_x509_certificate(pem.encode())
    return cert.public_bytes(serialization.Encoding.DER)


def _int_to_base64url(n: int, length: int) -> str:
    """Convert an integer to base64url encoding with fixed length."""
    return _base64url_encode(n.to_bytes(length, byteorder="big"))


def _get_jwk(key: PrivateKey) -> dict:
    """Get the JWK (JSON Web Key) representation of a public key."""
    if isinstance(key, rsa.RSAPrivateKey):
        public_key = key.public_key()
        public_numbers = public_key.public_numbers()
        # Calculate byte length for n (modulus)
        byte_length = (public_numbers.n.bit_length() + 7) // 8
        return {
            "kty": "RSA",
            "n": _base64url_encode(public_numbers.n.to_bytes(byte_length, byteorder="big")),
            "e": _base64url_encode(
                public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder="big")
            ),
        }
    else:
        # ECDSA key
        public_key = key.public_key()
        public_numbers = public_key.public_numbers()
        curve_name = public_key.curve.name

        # Determine curve and coordinate size
        if curve_name == "secp256r1":
            crv = "P-256"
            coord_size = 32
        elif curve_name == "secp384r1":
            crv = "P-384"
            coord_size = 48
        else:
            raise ValueError(f"Unsupported curve: {curve_name}")

        return {
            "kty": "EC",
            "crv": crv,
            "x": _int_to_base64url(public_numbers.x, coord_size),
            "y": _int_to_base64url(public_numbers.y, coord_size),
        }


def key_thumbprint(key: PrivateKey) -> str:
    """Compute the JWK thumbprint of a key (RFC 7638).

    Args:
        key: Private key to compute thumbprint for.

    Returns:
        Base64url-encoded SHA-256 thumbprint.
    """
    jwk = _get_jwk(key)

    # Thumbprint is computed from canonical JSON with sorted keys
    if jwk["kty"] == "RSA":
        # For RSA: {"e":...,"kty":"RSA","n":...}
        canonical = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    else:
        # For EC: {"crv":...,"kty":"EC","x":...,"y":...}
        canonical = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}

    # JSON encode with sorted keys and no spaces
    json_bytes = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")

    # SHA-256 hash and base64url encode
    digest = hashlib.sha256(json_bytes).digest()
    return _base64url_encode(digest)


def get_jwk(key: PrivateKey) -> dict:
    """Get the JWK (JSON Web Key) representation of a public key.

    This is the public API for getting JWK representation.

    Args:
        key: Private key to extract public JWK from.

    Returns:
        JWK dictionary.
    """
    return _get_jwk(key)


def sign_jws(
    key: PrivateKey,
    payload: dict | str,
    url: str,
    nonce: str | None = None,
    kid: str | None = None,
) -> str:
    """Sign a payload as a JWS (JSON Web Signature) for ACME.

    Args:
        key: Private key to sign with.
        payload: Payload to sign (dict for JSON, empty string for POST-as-GET).
        url: URL of the ACME endpoint.
        nonce: Replay nonce (optional for inner JWS in key rollover).
        kid: Account URL (if registered). If None, includes JWK.

    Returns:
        JWS in compact serialization format (header.payload.signature).
    """
    # Determine algorithm based on key type
    if isinstance(key, rsa.RSAPrivateKey):
        alg = "RS256"
    else:
        curve_name = key.public_key().curve.name
        if curve_name == "secp256r1":
            alg = "ES256"
        elif curve_name == "secp384r1":
            alg = "ES384"
        else:
            raise ValueError(f"Unsupported curve: {curve_name}")

    # Build protected header
    protected: dict[str, str | dict] = {
        "alg": alg,
        "url": url,
    }

    # Only include nonce if provided (inner JWS in key rollover has no nonce)
    if nonce is not None:
        protected["nonce"] = nonce

    if kid:
        protected["kid"] = kid
    else:
        protected["jwk"] = _get_jwk(key)

    # Encode header
    protected_b64 = _base64url_encode(json.dumps(protected, separators=(",", ":")).encode("utf-8"))

    # Encode payload
    if payload == "":
        payload_b64 = ""
    else:
        payload_b64 = _base64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))

    # Create signing input
    signing_input = f"{protected_b64}.{payload_b64}".encode()

    # Sign
    if isinstance(key, rsa.RSAPrivateKey):
        signature = key.sign(
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    else:
        # ECDSA signature
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        der_signature = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_signature)

        # Convert to fixed-size concatenated r||s format
        curve_name = key.public_key().curve.name
        coord_size = 32 if curve_name == "secp256r1" else 48

        r_bytes = r.to_bytes(coord_size, byteorder="big")
        s_bytes = s.to_bytes(coord_size, byteorder="big")
        signature = r_bytes + s_bytes

    signature_b64 = _base64url_encode(signature)

    return f"{protected_b64}.{payload_b64}.{signature_b64}"
