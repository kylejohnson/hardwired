"""ACME client for certificate management."""

import json

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from hardwired.crypto import (
    base64url_encode,
    create_csr,
    get_jwk,
    key_thumbprint,
    pem_to_der,
    sign_jws,
)
from hardwired.exceptions import AcmeError, BadNonceError
from hardwired.models import (
    Account,
    Authorization,
    AuthorizationInfo,
    CertificateResult,
    Challenge,
    Directory,
    Order,
)
from hardwired.providers.base import DnsProvider

# Type alias for private keys
PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey


class AcmeClient:
    """ACME client for automated SSL/TLS certificate management.

    This client implements RFC 8555 (ACME) for obtaining certificates
    from an ACME-compliant certificate authority.

    Args:
        directory_url: URL of the ACME directory endpoint.
        account_key: Private key for the ACME account.
        dns_provider: DNS provider for DNS-01 challenge validation.
        ca_cert: Path to CA certificate file, False to disable verification,
                 or None/True for default verification.
    """

    # Polling configuration
    POLL_INTERVAL = 2  # seconds
    MAX_POLL_ATTEMPTS = 30  # 60 seconds total

    def __init__(
        self,
        directory_url: str,
        account_key: PrivateKey,
        dns_provider: DnsProvider,
        ca_cert: str | bool | None = None,
    ):
        self.directory_url = directory_url
        self.account_key = account_key
        self.dns_provider = dns_provider

        # HTTP client with SSL verification setting
        # ca_cert can be: path (str), False (disable), None/True (default)
        verify = True if ca_cert is None else ca_cert
        self._http = httpx.Client(verify=verify)

        # Cached state
        self._directory: Directory | None = None
        self._nonce: str | None = None
        self._account_url: str | None = None

    def close(self) -> None:
        """Close the HTTP client."""
        self._http.close()

    def __enter__(self) -> "AcmeClient":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    @property
    def directory(self) -> Directory:
        """Get the ACME directory (cached after first fetch)."""
        if self._directory is None:
            response = self._http.get(self.directory_url)
            response.raise_for_status()
            self._directory = Directory.model_validate(response.json())
        return self._directory

    @property
    def account_url(self) -> str | None:
        """Get the account URL (set after registration)."""
        return self._account_url

    def _get_nonce(self) -> str:
        """Get a fresh nonce from the ACME server."""
        if self._nonce:
            nonce = self._nonce
            self._nonce = None
            return nonce

        response = self._http.head(self.directory.new_nonce)
        response.raise_for_status()
        return response.headers["Replay-Nonce"]

    def _update_nonce(self, response: httpx.Response) -> None:
        """Update the cached nonce from response headers."""
        if "Replay-Nonce" in response.headers:
            self._nonce = response.headers["Replay-Nonce"]

    def _signed_request(
        self,
        url: str,
        payload: dict | str,
        use_kid: bool = True,
        _retry_count: int = 0,
    ) -> httpx.Response:
        """Make a JWS-signed POST request to the ACME server.

        Args:
            url: The endpoint URL.
            payload: The request payload (dict for JSON, "" for POST-as-GET).
            use_kid: If True, use kid (account URL) in JWS header.
                     If False, use jwk (for new account registration).

        Returns:
            The HTTP response.

        Raises:
            AcmeError: If the ACME server returns an error.
        """
        nonce = self._get_nonce()

        kid = self._account_url if use_kid else None

        jws = sign_jws(
            key=self.account_key,
            payload=payload,
            url=url,
            nonce=nonce,
            kid=kid,
        )

        # ACME uses JWS JSON Flattened Serialization
        parts = jws.split(".")
        body = {
            "protected": parts[0],
            "payload": parts[1],
            "signature": parts[2],
        }

        response = self._http.post(
            url,
            json=body,
            headers={"Content-Type": "application/jose+json"},
        )

        # Always update nonce from response
        self._update_nonce(response)

        # Check for errors
        if response.status_code >= 400:
            try:
                error_data = response.json()
                error = AcmeError.from_response(
                    error_data,
                    response.status_code,
                    headers=dict(response.headers),
                )

                # Retry on bad nonce errors (pebble rejects 5% of good nonces)
                if isinstance(error, BadNonceError) and _retry_count < 3:
                    # Get fresh nonce and retry
                    self._nonce = None  # Force fresh nonce
                    return self._signed_request(url, payload, use_kid, _retry_count + 1)

                raise error
            except json.JSONDecodeError:
                raise AcmeError(
                    type="unknown",
                    detail=response.text,
                    status_code=response.status_code,
                ) from None

        return response

    def register_account(self, email: str | None = None) -> Account:
        """Register a new account or find an existing one.

        If an account already exists for the key, it will be returned.
        Otherwise, a new account is created.

        Args:
            email: Contact email address (optional).

        Returns:
            The Account resource.
        """
        payload: dict = {
            "termsOfServiceAgreed": True,
        }

        if email:
            payload["contact"] = [f"mailto:{email}"]

        response = self._signed_request(
            self.directory.new_account,
            payload,
            use_kid=False,  # New accounts use jwk, not kid
        )

        # Store account URL from Location header
        self._account_url = response.headers.get("Location")

        return Account.model_validate(response.json())

    def rollover_key(self, new_key: PrivateKey) -> None:
        """Roll over to a new account key (RFC 8555 Section 7.3.5).

        This changes the key associated with the account. After rollover,
        the client will use the new key for all subsequent requests.

        Args:
            new_key: The new private key to use for the account.

        Raises:
            AcmeError: If key rollover fails.
            ValueError: If account is not registered.
        """
        if not self._account_url:
            raise ValueError("Account not registered. Call register_account() first.")

        key_change_url = self.directory.key_change

        # Inner JWS payload: account URL and old key's JWK
        inner_payload = {
            "account": self._account_url,
            "oldKey": get_jwk(self.account_key),
        }

        # Create inner JWS signed by NEW key (no nonce for inner JWS)
        inner_jws = sign_jws(
            key=new_key,
            payload=inner_payload,
            url=key_change_url,
            nonce=None,  # Inner JWS has no nonce per RFC 8555
            kid=None,  # Uses jwk (new key), not kid
        )

        # Convert inner JWS from compact to JSON Flattened Serialization
        # for use as the outer JWS payload
        inner_protected, inner_payload_b64, inner_sig = inner_jws.split(".")
        inner_jws_json = {
            "protected": inner_protected,
            "payload": inner_payload_b64,
            "signature": inner_sig,
        }

        # Send outer JWS signed by OLD key with inner JWS as payload
        self._signed_request(key_change_url, inner_jws_json)

        # Update internal key reference
        self.account_key = new_key

    def deactivate_account(self) -> None:
        """Deactivate the current account (RFC 8555 Section 7.3.6).

        WARNING: This is irreversible. A deactivated account cannot be
        reactivated, and no new orders can be created.

        Raises:
            AcmeError: If deactivation fails.
            ValueError: If account is not registered.
        """
        if not self._account_url:
            raise ValueError("Account not registered. Call register_account() first.")

        payload = {"status": "deactivated"}
        self._signed_request(self._account_url, payload)

    def create_order(self, domains: list[str]) -> Order:
        """Create a new certificate order.

        Args:
            domains: List of domain names for the certificate.

        Returns:
            The Order resource.
        """
        identifiers = [{"type": "dns", "value": domain} for domain in domains]

        payload = {"identifiers": identifiers}

        response = self._signed_request(
            self.directory.new_order,
            payload,
        )

        order = Order.model_validate(response.json())

        # Store the order URL for later operations
        order_url = response.headers.get("Location")
        if order_url:
            # Attach order URL as an attribute for convenience
            object.__setattr__(order, "_url", order_url)

        return order

    def fetch_authorizations(self, order: Order) -> list[Authorization]:
        """Fetch all authorizations for an order.

        Args:
            order: The order to fetch authorizations for.

        Returns:
            List of Authorization resources.
        """
        authorizations = []
        for authz_url in order.authorizations:
            response = self._signed_request(authz_url, "")
            authz = Authorization.model_validate(response.json())
            # Store the URL on the authorization
            object.__setattr__(authz, "_url", authz_url)
            authorizations.append(authz)
        return authorizations

    def deactivate_authorization(self, authz_url: str) -> Authorization:
        """Deactivate an authorization (RFC 8555 Section 7.5.2).

        This prevents the authorization from being used to issue certificates.
        Use this when selling/transferring a domain to ensure no new certificates
        can be issued for it.

        Args:
            authz_url: The authorization URL to deactivate.

        Returns:
            The updated Authorization with status "deactivated".
        """
        payload = {"status": "deactivated"}
        response = self._signed_request(authz_url, payload)
        return Authorization.model_validate(response.json())

    def get_challenge(
        self, authorization: Authorization, challenge_type: str = "dns-01"
    ) -> Challenge:
        """Get a specific challenge from an authorization.

        Args:
            authorization: The authorization containing challenges.
            challenge_type: Type of challenge to get (e.g., "dns-01").

        Returns:
            The Challenge resource.

        Raises:
            ValueError: If the challenge type is not found.
        """
        for challenge in authorization.challenges:
            if challenge.type == challenge_type:
                return challenge
        raise ValueError(f"Challenge type '{challenge_type}' not found in authorization")

    def complete_challenge(
        self,
        challenge: Challenge,
        authorization: Authorization,
        skip_dns_setup: bool = False,
    ) -> Challenge:
        """Complete a DNS-01 challenge.

        This method:
        1. Sets up the DNS TXT record (unless skip_dns_setup=True)
        2. Responds to the challenge
        3. Polls until the challenge is valid or invalid
        4. Cleans up the DNS record

        Args:
            challenge: The challenge to complete.
            authorization: The authorization containing the challenge.
            skip_dns_setup: If True, skip DNS record creation (for testing).

        Returns:
            The validated Challenge resource.

        Raises:
            AcmeError: If challenge validation fails.
        """
        domain = authorization.identifier.value
        thumbprint = key_thumbprint(self.account_key)
        key_authorization = f"{challenge.token}.{thumbprint}"

        # Compute the DNS TXT value (base64url-encoded SHA-256 of key authorization)
        import base64
        import hashlib

        txt_value = (
            base64.urlsafe_b64encode(hashlib.sha256(key_authorization.encode()).digest())
            .rstrip(b"=")
            .decode()
        )

        try:
            if not skip_dns_setup:
                # Set up DNS record
                self.dns_provider.create_txt_record(domain, txt_value)
                self.dns_provider.wait_for_propagation(domain, txt_value)

            # Respond to challenge (empty object)
            self._signed_request(challenge.url, {})

            # Poll for challenge status
            return self._poll_challenge(challenge.url)
        finally:
            if not skip_dns_setup:
                # Clean up DNS record
                import contextlib

                with contextlib.suppress(Exception):
                    self.dns_provider.delete_txt_record(domain, txt_value)

    def _poll_challenge(self, challenge_url: str) -> Challenge:
        """Poll a challenge until it's valid or invalid."""
        import time

        for _ in range(self.MAX_POLL_ATTEMPTS):
            response = self._signed_request(challenge_url, "")
            challenge = Challenge.model_validate(response.json())

            if challenge.status == "valid":
                return challenge
            elif challenge.status == "invalid":
                error_detail = "Challenge validation failed"
                if challenge.error:
                    error_detail = challenge.error.get("detail", error_detail)
                raise AcmeError(
                    type="urn:ietf:params:acme:error:unauthorized",
                    detail=error_detail,
                    status_code=403,
                )
            elif challenge.status in ("pending", "processing"):
                time.sleep(self.POLL_INTERVAL)
            else:
                raise AcmeError(
                    type="urn:ietf:params:acme:error:serverInternal",
                    detail=f"Unexpected challenge status: {challenge.status}",
                    status_code=500,
                )

        raise AcmeError(
            type="urn:ietf:params:acme:error:serverInternal",
            detail="Challenge polling timed out",
            status_code=500,
        )

    def _poll_order(self, order_url: str) -> Order:
        """Poll an order until it's ready or invalid."""
        import time

        for _ in range(self.MAX_POLL_ATTEMPTS):
            response = self._signed_request(order_url, "")
            order = Order.model_validate(response.json())

            if order.status == "ready" or order.status == "valid":
                return order
            elif order.status == "invalid":
                error_detail = "Order is invalid"
                if order.error:
                    error_detail = order.error.get("detail", error_detail)
                raise AcmeError(
                    type="urn:ietf:params:acme:error:orderNotReady",
                    detail=error_detail,
                    status_code=403,
                )
            elif order.status in ("pending", "processing"):
                time.sleep(self.POLL_INTERVAL)
            else:
                raise AcmeError(
                    type="urn:ietf:params:acme:error:serverInternal",
                    detail=f"Unexpected order status: {order.status}",
                    status_code=500,
                )

        raise AcmeError(
            type="urn:ietf:params:acme:error:serverInternal",
            detail="Order polling timed out",
            status_code=500,
        )

    def finalize_order(
        self,
        order: Order,
        csr: x509.CertificateSigningRequest,
    ) -> Order:
        """Finalize an order by submitting the CSR.

        Args:
            order: The order to finalize.
            csr: The Certificate Signing Request.

        Returns:
            The finalized Order resource.
        """
        import base64

        # Encode CSR in base64url DER format
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        csr_b64 = base64.urlsafe_b64encode(csr_der).rstrip(b"=").decode()

        payload = {"csr": csr_b64}

        response = self._signed_request(order.finalize, payload)
        return Order.model_validate(response.json())

    def download_certificate(self, order: Order) -> str:
        """Download the certificate for a finalized order.

        Args:
            order: The order with certificate URL.

        Returns:
            The certificate chain in PEM format.

        Raises:
            ValueError: If order has no certificate URL.
        """
        if not order.certificate:
            raise ValueError("Order has no certificate URL")

        response = self._signed_request(order.certificate, "")
        return response.text

    def revoke_certificate(
        self,
        certificate_pem: str,
        reason: int | None = None,
    ) -> None:
        """Revoke a certificate (RFC 8555 Section 7.6).

        Args:
            certificate_pem: The PEM-encoded certificate to revoke.
            reason: Optional revocation reason code (RFC 5280 Section 5.3.1):
                    0 = unspecified
                    1 = keyCompromise
                    2 = cACompromise
                    3 = affiliationChanged
                    4 = superseded
                    5 = cessationOfOperation
                    6 = certificateHold

        Raises:
            AcmeError: If revocation fails.
        """
        # Convert PEM to DER and base64url encode
        try:
            der_bytes = pem_to_der(certificate_pem)
        except ValueError as e:
            raise AcmeError(
                type="urn:ietf:params:acme:error:malformed",
                detail=f"Invalid certificate PEM: {e}",
                status_code=400,
            ) from e
        cert_b64 = base64url_encode(der_bytes)

        # Build payload
        payload: dict[str, str | int] = {"certificate": cert_b64}
        if reason is not None:
            payload["reason"] = reason

        # POST to revokeCert endpoint
        self._signed_request(self.directory.revoke_cert, payload)

    def obtain_certificate(
        self,
        domains: list[str],
        csr: x509.CertificateSigningRequest | None = None,
    ) -> CertificateResult:
        """Obtain a certificate for the given domains.

        This is the main high-level method that:
        1. Creates an order
        2. Completes all authorizations via DNS-01
        3. Finalizes the order with a CSR
        4. Downloads the certificate

        Args:
            domains: List of domain names for the certificate.
            csr: Optional CSR. If not provided, one will be generated.

        Returns:
            CertificateResult with certificate_pem, private_key_pem, and expires_at.
        """
        # Generate CSR if not provided
        private_key_pem: str | None = None
        if csr is None:
            cert_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            csr = create_csr(cert_key, domains)
            private_key_pem = cert_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode()

        # Create order
        order = self.create_order(domains)
        order_url = getattr(order, "_url", None)

        # Complete all authorizations
        authorizations = self.fetch_authorizations(order)
        for authz in authorizations:
            if authz.status != "valid":
                challenge = self.get_challenge(authz, "dns-01")
                self.complete_challenge(challenge, authz)

        # Poll order until ready
        if order_url:
            order = self._poll_order(order_url)

        # Finalize order
        order = self.finalize_order(order, csr)

        # Poll for certificate
        if order_url and not order.certificate:
            for _ in range(self.MAX_POLL_ATTEMPTS):
                import time

                time.sleep(self.POLL_INTERVAL)
                response = self._signed_request(order_url, "")
                order = Order.model_validate(response.json())
                if order.certificate:
                    break

        # Download certificate
        certificate_pem = self.download_certificate(order)

        # Parse certificate to get expiration
        cert = x509.load_pem_x509_certificate(certificate_pem.encode())
        expires_at = cert.not_valid_after_utc

        # Build authorization info for deactivation support
        authz_info_list: list[AuthorizationInfo] = []
        for authz in authorizations:
            authz_url = getattr(authz, "_url", None)
            if authz_url and authz.expires:
                authz_info_list.append(
                    AuthorizationInfo(
                        url=authz_url,
                        domain=authz.identifier.value,
                        expires_at=authz.expires,
                    )
                )

        return CertificateResult(
            certificate_pem=certificate_pem,
            private_key_pem=private_key_pem,
            expires_at=expires_at,
            domains=domains,
            authorizations=authz_info_list,
        )
