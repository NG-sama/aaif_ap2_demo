"""Create and verify DPoP proofs (RFC 9449).

A DPoP proof is a JWS the client signs *per HTTP request* with the private key
it holds. It proves "whoever sent this request also holds the key the access
token is bound to". Contrast a static bearer token, which proves only "whoever
sent this request has a copy of the token".

Proof JOSE header:  ``{"typ": "dpop+jwt", "alg": "ES256", "jwk": <public key>}``
Proof claims:       ``jti`` (unique id), ``htm`` (HTTP method),
                    ``htu`` (HTTP URI, no query/fragment), ``iat`` (issued-at),
                    ``nonce`` (server-supplied, optional),
                    ``ath`` (SHA-256 of the access token, when one is presented).
"""

from __future__ import annotations

import secrets
import time
from urllib.parse import urlsplit, urlunsplit

from cryptography.hazmat.primitives.asymmetric import ec

from . import crypto

PROOF_TYP = "dpop+jwt"


class DPoPError(ValueError):
    """Base class; ``code`` maps to the RFC 9449 error identifier."""

    code = "invalid_dpop_proof"


class InvalidProof(DPoPError):
    code = "invalid_dpop_proof"


class UseDPoPNonce(DPoPError):
    """The server requires a (fresh) nonce in the proof."""

    code = "use_dpop_nonce"


def normalize_htu(url: str) -> str:
    """`htu` is the request URI with query and fragment removed (RFC 9449 4.3)."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def create_proof(
    key: ec.EllipticCurvePrivateKey,
    htm: str,
    htu: str,
    *,
    nonce: str | None = None,
    access_token: str | None = None,
    iat: int | None = None,
    jti: str | None = None,
) -> str:
    header = {"typ": PROOF_TYP, "alg": crypto.JOSE_ALG, "jwk": crypto.public_jwk(key)}
    claims: dict[str, object] = {
        "jti": jti or secrets.token_urlsafe(16),
        "htm": htm.upper(),
        "htu": normalize_htu(htu),
        "iat": iat if iat is not None else int(time.time()),
    }
    if nonce is not None:
        claims["nonce"] = nonce
    if access_token is not None:
        claims["ath"] = crypto.access_token_hash(access_token)
    return crypto.jws_sign(header, claims, key)


def verify_proof(
    compact: str,
    *,
    htm: str,
    htu: str,
    replay_cache,
    now: float | None = None,
    leeway: int = 60,
    expected_ath: str | None = None,
    require_nonce: bool = False,
    current_nonce: str | None = None,
) -> str:
    """Validate a proof and return the caller's key thumbprint (``jkt``).

    Raises ``UseDPoPNonce`` when a nonce is required but missing/stale, and
    ``InvalidProof`` for every other failure.
    """
    now = time.time() if now is None else now

    # 1. Header shape + pull the client's public key out of the header.
    header = crypto.peek_jws_header(compact)
    if header.get("typ") != PROOF_TYP:
        raise InvalidProof(f"typ must be {PROOF_TYP!r}")
    if header.get("alg") != crypto.JOSE_ALG:
        raise InvalidProof(f"alg must be {crypto.JOSE_ALG!r}")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict) or "d" in jwk:
        raise InvalidProof("header must carry a public jwk")

    # 2. Signature must verify against that embedded key.
    try:
        pub = crypto.jwk_to_public_key(jwk)
        _, claims = crypto.jws_verify(compact, pub)
    except (crypto.JWSError, ValueError) as exc:
        raise InvalidProof(f"bad proof signature: {exc}") from exc

    # 3. Method / URI binding.
    if str(claims.get("htm", "")).upper() != htm.upper():
        raise InvalidProof("htm mismatch")
    if claims.get("htu") != normalize_htu(htu):
        raise InvalidProof("htu mismatch")

    # 4. Freshness + anti-replay.
    iat = claims.get("iat")
    if not isinstance(iat, (int, float)) or abs(now - iat) > leeway:
        raise InvalidProof("iat outside acceptance window")
    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti:
        raise InvalidProof("missing jti")
    try:
        replay_cache.check_and_add(jti, now=now)
    except Exception as exc:  # ReplayError
        raise InvalidProof(str(exc)) from exc

    # 5. Access-token binding (only when the request presents one).
    if expected_ath is not None and claims.get("ath") != expected_ath:
        raise InvalidProof("ath does not match the presented access token")

    # 6. Server nonce challenge (RFC 9449 section 8).
    if require_nonce and claims.get("nonce") != current_nonce:
        raise UseDPoPNonce("missing or stale nonce")

    return crypto.jwk_thumbprint(jwk)
