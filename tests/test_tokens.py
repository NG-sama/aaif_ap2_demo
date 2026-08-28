import time

import pytest

from aaif_ap2_demo import crypto, tokens

AUD = "https://rs.example/mcp"
ISS = "https://as.example"


def _mint(**over):
    args = dict(jkt="JKT123", client_id="agent-1", scope="payments:read", audience=AUD, issuer=ISS, ttl_seconds=30)
    args.update(over)
    return tokens.mint_access_token(**args)


def test_mint_and_verify_roundtrip():
    tok = _mint()
    claims = tokens.verify_access_token(tok, audience=AUD)
    assert claims["cnf"]["jkt"] == "JKT123"
    assert claims["sub"] == "agent-1"
    assert claims["scope"] == "payments:read"


def test_wrong_audience_rejected():
    tok = _mint()
    with pytest.raises(tokens.TokenError):
        tokens.verify_access_token(tok, audience="https://other.example/mcp")


def test_expired_token_rejected():
    tok = _mint(ttl_seconds=1, now=int(time.time()) - 3600)
    with pytest.raises(tokens.TokenError):
        tokens.verify_access_token(tok, audience=AUD)


def test_tampered_signature_rejected():
    head, payload, _sig = _mint().split(".")
    forged = crypto.b64u_encode(b'{"iss":"x","aud":"' + AUD.encode() + b'","exp":9999999999,"cnf":{"jkt":"evil"}}')
    with pytest.raises(tokens.TokenError):
        tokens.verify_access_token(f"{head}.{forged}.{_sig}", audience=AUD)


def test_bearer_style_token_without_cnf_rejected():
    # A token minted by a different signer / without cnf must not pass.
    key = crypto.generate_ec_keypair()
    now = int(time.time())
    fake = crypto.jws_sign(
        {"typ": "at+jwt", "alg": "ES256"},
        {"iss": ISS, "sub": "x", "aud": AUD, "iat": now, "exp": now + 60},
        key,
    )
    with pytest.raises(tokens.TokenError):
        tokens.verify_access_token(fake, audience=AUD)
