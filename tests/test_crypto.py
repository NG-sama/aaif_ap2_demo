from aaif_ap2_demo import crypto


def test_jwk_thumbprint_known_answer():
    # JWK + thumbprint from RFC 9449 section 6.1.
    jwk = {
        "kty": "EC",
        "x": "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
        "y": "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
        "crv": "P-256",
    }
    assert crypto.jwk_thumbprint(jwk) == "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"


def test_jwk_thumbprint_is_member_order_independent():
    a = {"kty": "EC", "crv": "P-256", "x": "AA", "y": "BB"}
    b = {"y": "BB", "x": "AA", "crv": "P-256", "kty": "EC", "extra": "ignored"}
    # `extra` is not one of the required members, so it must not change the hash.
    b.pop("extra")
    assert crypto.jwk_thumbprint(a) == crypto.jwk_thumbprint(b)


def test_jws_sign_verify_roundtrip():
    key = crypto.generate_ec_keypair()
    compact = crypto.jws_sign({"alg": "ES256", "typ": "x"}, {"hello": "world", "n": 1}, key)
    header, payload = crypto.jws_verify(compact, key.public_key())
    assert header["alg"] == "ES256"
    assert payload == {"hello": "world", "n": 1}


def test_jws_verify_rejects_tampered_payload():
    key = crypto.generate_ec_keypair()
    h, p, s = crypto.jws_sign({"alg": "ES256"}, {"amount": 1}, key).split(".")
    forged_payload = crypto.b64u_encode(b'{"amount":1000000}')
    try:
        crypto.jws_verify(f"{h}.{forged_payload}.{s}", key.public_key())
    except crypto.JWSError:
        return
    raise AssertionError("tampered JWS verified")


def test_jws_verify_rejects_other_key():
    k1, k2 = crypto.generate_ec_keypair(), crypto.generate_ec_keypair()
    compact = crypto.jws_sign({"alg": "ES256"}, {"a": 1}, k1)
    try:
        crypto.jws_verify(compact, k2.public_key())
    except crypto.JWSError:
        return
    raise AssertionError("verified under the wrong key")


def test_public_jwk_roundtrips_through_jwk_to_public_key():
    key = crypto.generate_ec_keypair()
    jwk = crypto.public_jwk(key)
    reconstructed = crypto.jwk_to_public_key(jwk)
    assert crypto.public_jwk(reconstructed) == jwk
