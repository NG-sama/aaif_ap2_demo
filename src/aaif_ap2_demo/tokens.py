"""The toy Authorization Server: mint and verify short-lived, key-bound access
tokens.

The token is a JWS signed by the AS. What makes it a *DPoP* access token rather
than a bearer token is the ``cnf`` (confirmation) claim: ``cnf.jkt`` is the
RFC 7638 thumbprint of the client's public key (RFC 9449 section 6). The
resource server later checks that the DPoP proof on the request was signed by
the key with that thumbprint. Steal the token without the key and it is inert.
"""

from __future__ import annotations

import secrets
import time

from cryptography.hazmat.primitives.asymmetric import ec

from . import crypto
from .config import DEV_KEYS_DIR

_AS_KEY_PATH = DEV_KEYS_DIR / "as_signing_key.pem"


class TokenError(ValueError):
    code = "invalid_token"


def as_signing_key() -> ec.EllipticCurvePrivateKey:
    return crypto.load_or_create_private_key(_AS_KEY_PATH)


def mint_access_token(
    *,
    jkt: str,
    client_id: str,
    scope: str,
    audience: str,
    issuer: str,
    ttl_seconds: int,
    now: int | None = None,
) -> str:
    now = int(time.time()) if now is None else now
    header = {"typ": "at+jwt", "alg": crypto.JOSE_ALG}
    claims = {
        "iss": issuer,
        "sub": client_id,
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + ttl_seconds,
        "jti": secrets.token_urlsafe(12),
        "scope": scope,
        "cnf": {"jkt": jkt},  # <-- the proof-of-possession binding
    }
    return crypto.jws_sign(header, claims, as_signing_key())


def verify_access_token(token: str, *, audience: str, now: int | None = None) -> dict:
    """Return the token claims, or raise ``TokenError``."""
    now = int(time.time()) if now is None else now
    try:
        _, claims = crypto.jws_verify(token, as_signing_key().public_key())
    except crypto.JWSError as exc:
        raise TokenError(f"bad token signature: {exc}") from exc

    if claims.get("aud") != audience:
        raise TokenError("wrong audience")
    if not isinstance(claims.get("exp"), (int, float)) or now >= claims["exp"]:
        raise TokenError("token expired")
    if isinstance(claims.get("nbf"), (int, float)) and now < claims["nbf"]:
        raise TokenError("token not yet valid")
    if "cnf" not in claims or "jkt" not in claims["cnf"]:
        raise TokenError("token is not DPoP-bound (no cnf.jkt)")
    return claims
