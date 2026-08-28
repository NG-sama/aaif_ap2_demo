"""The crypto primitives, hand-rolled on top of ``cryptography`` so every byte
that goes on the wire is visible in this file.

Nothing here is novel: it is JWS (RFC 7515) with the ``ES256`` algorithm
(ECDSA on NIST P-256 + SHA-256), JWK for public keys (RFC 7517), and the JWK
thumbprint from RFC 7638. A DPoP proof (RFC 9449) is just a JWS with a
particular header (`typ: "dpop+jwt"`, the public `jwk` inline) and a particular
set of claims. Seeing it spelled out is the point of the prototype.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

_CURVE = ec.SECP256R1()  # a.k.a. "P-256" in JOSE / prime256v1 in OpenSSL
_COORD_BYTES = 32  # P-256 field elements are 32 bytes
JOSE_ALG = "ES256"
JWK_CRV = "P-256"


# --------------------------------------------------------------------------- #
# base64url            (RFC 7515 Appendix C: no padding, URL-safe alphabet)
# --------------------------------------------------------------------------- #
def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(txt: str) -> bytes:
    pad = "=" * (-len(txt) % 4)
    return base64.urlsafe_b64decode(txt + pad)


def _json_compact(obj: Any) -> bytes:
    """Smallest-possible JSON: no spaces. Used for JWS segments."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# --------------------------------------------------------------------------- #
# Key handling
# --------------------------------------------------------------------------- #
def generate_ec_keypair() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(_CURVE)


def public_jwk(key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey) -> dict[str, str]:
    """The public half of an EC key as a JWK dict (RFC 7518 section 6.2.1)."""
    pub = key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
    nums = pub.public_numbers()
    return {
        "kty": "EC",
        "crv": JWK_CRV,
        "x": b64u_encode(nums.x.to_bytes(_COORD_BYTES, "big")),
        "y": b64u_encode(nums.y.to_bytes(_COORD_BYTES, "big")),
    }


def jwk_to_public_key(jwk: dict[str, str]) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != JWK_CRV:
        raise ValueError(f"unsupported jwk: {jwk.get('kty')}/{jwk.get('crv')}")
    x = int.from_bytes(b64u_decode(jwk["x"]), "big")
    y = int.from_bytes(b64u_decode(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, _CURVE).public_key()


def jwk_thumbprint(jwk: dict[str, str]) -> str:
    """RFC 7638 JWK thumbprint (SHA-256), base64url.

    The canonical form is a JSON object with ONLY the required members, in
    lexicographic key order, no whitespace. For an EC key that is
    ``{"crv","kty","x","y"}``. This value is the ``jkt`` that binds an access
    token to a key (RFC 9449 section 6.1).
    """
    canonical = _json_compact(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
    )
    return b64u_encode(hashlib.sha256(canonical).digest())


def key_thumbprint(key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey) -> str:
    return jwk_thumbprint(public_jwk(key))


# --------------------------------------------------------------------------- #
# Persist keys so the scenarios can deliberately share / "steal" them
# --------------------------------------------------------------------------- #
def save_private_key(key: ec.EllipticCurvePrivateKey, path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def load_private_key(path) -> ec.EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)  # type: ignore[return-value]


def load_or_create_private_key(path) -> ec.EllipticCurvePrivateKey:
    if path.exists():
        return load_private_key(path)
    key = generate_ec_keypair()
    save_private_key(key, path)
    return key


# --------------------------------------------------------------------------- #
# JWS compact serialization with ES256
# --------------------------------------------------------------------------- #
def _der_to_raw(der_sig: bytes) -> bytes:
    """ES256 signatures on the wire are fixed-width r||s (RFC 7518 3.4);
    ``cryptography`` emits/consumes DER, so convert."""
    r, s = decode_dss_signature(der_sig)
    return r.to_bytes(_COORD_BYTES, "big") + s.to_bytes(_COORD_BYTES, "big")


def _raw_to_der(raw_sig: bytes) -> bytes:
    if len(raw_sig) != 2 * _COORD_BYTES:
        raise ValueError("bad ES256 signature length")
    r = int.from_bytes(raw_sig[:_COORD_BYTES], "big")
    s = int.from_bytes(raw_sig[_COORD_BYTES:], "big")
    return encode_dss_signature(r, s)


def jws_sign(header: dict[str, Any], payload: dict[str, Any], key: ec.EllipticCurvePrivateKey) -> str:
    signing_input = b64u_encode(_json_compact(header)) + "." + b64u_encode(_json_compact(payload))
    der = key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    return signing_input + "." + b64u_encode(_der_to_raw(der))


class JWSError(ValueError):
    """Signature did not verify, or the compact serialization was malformed."""


def jws_verify(compact: str, key: ec.EllipticCurvePublicKey) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        h_b64, p_b64, s_b64 = compact.split(".")
    except ValueError as exc:
        raise JWSError("not a 3-part compact JWS") from exc
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    try:
        key.verify(_raw_to_der(b64u_decode(s_b64)), signing_input, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError) as exc:
        raise JWSError("signature verification failed") from exc
    try:
        return json.loads(b64u_decode(h_b64)), json.loads(b64u_decode(p_b64))
    except json.JSONDecodeError as exc:
        raise JWSError("header/payload not JSON") from exc


def peek_jws_header(compact: str) -> dict[str, Any]:
    """Read the JOSE header WITHOUT verifying — needed because the verifying key
    (`jwk`) lives inside the header of a DPoP proof."""
    try:
        h_b64 = compact.split(".", 1)[0]
        return json.loads(b64u_decode(h_b64))
    except (ValueError, json.JSONDecodeError) as exc:
        raise JWSError("cannot read JWS header") from exc


# --------------------------------------------------------------------------- #
# Access-token binding hash  (RFC 9449 section 4.2, the `ath` claim)
# --------------------------------------------------------------------------- #
def access_token_hash(access_token: str) -> str:
    return b64u_encode(hashlib.sha256(access_token.encode("ascii")).digest())
