import time

import pytest

from aaif_ap2_demo import crypto, dpop
from aaif_ap2_demo.replay_cache import SeenJTICache

HTU = "https://rs.example/mcp"
HTM = "POST"


def _cache():
    return SeenJTICache(ttl_seconds=300)


def test_happy_path_returns_caller_thumbprint():
    key = crypto.generate_ec_keypair()
    proof = dpop.create_proof(key, HTM, HTU + "?ignored=1")
    jkt = dpop.verify_proof(proof, htm=HTM, htu=HTU, replay_cache=_cache())
    assert jkt == crypto.key_thumbprint(key)


def test_htm_mismatch():
    key = crypto.generate_ec_keypair()
    proof = dpop.create_proof(key, "POST", HTU)
    with pytest.raises(dpop.InvalidProof):
        dpop.verify_proof(proof, htm="GET", htu=HTU, replay_cache=_cache())


def test_htu_mismatch():
    key = crypto.generate_ec_keypair()
    proof = dpop.create_proof(key, HTM, "https://rs.example/other")
    with pytest.raises(dpop.InvalidProof):
        dpop.verify_proof(proof, htm=HTM, htu=HTU, replay_cache=_cache())


def test_stale_iat():
    key = crypto.generate_ec_keypair()
    proof = dpop.create_proof(key, HTM, HTU, iat=int(time.time()) - 3600)
    with pytest.raises(dpop.InvalidProof):
        dpop.verify_proof(proof, htm=HTM, htu=HTU, replay_cache=_cache(), leeway=60)


def test_replayed_jti():
    key = crypto.generate_ec_keypair()
    cache = _cache()
    proof = dpop.create_proof(key, HTM, HTU, jti="fixed-jti")
    dpop.verify_proof(proof, htm=HTM, htu=HTU, replay_cache=cache)
    with pytest.raises(dpop.InvalidProof):
        dpop.verify_proof(proof, htm=HTM, htu=HTU, replay_cache=cache)


def test_ath_binding():
    key = crypto.generate_ec_keypair()
    proof = dpop.create_proof(key, HTM, HTU, access_token="token-A")
    # correct
    dpop.verify_proof(
        proof, htm=HTM, htu=HTU, replay_cache=_cache(), expected_ath=crypto.access_token_hash("token-A")
    )
    # wrong token
    with pytest.raises(dpop.InvalidProof):
        dpop.verify_proof(
            proof, htm=HTM, htu=HTU, replay_cache=_cache(), expected_ath=crypto.access_token_hash("token-B")
        )


def test_missing_nonce_raises_use_dpop_nonce():
    key = crypto.generate_ec_keypair()
    proof = dpop.create_proof(key, HTM, HTU)  # no nonce
    with pytest.raises(dpop.UseDPoPNonce):
        dpop.verify_proof(
            proof, htm=HTM, htu=HTU, replay_cache=_cache(), require_nonce=True, current_nonce="srv-nonce"
        )


def test_correct_nonce_accepted():
    key = crypto.generate_ec_keypair()
    proof = dpop.create_proof(key, HTM, HTU, nonce="srv-nonce")
    jkt = dpop.verify_proof(
        proof, htm=HTM, htu=HTU, replay_cache=_cache(), require_nonce=True, current_nonce="srv-nonce"
    )
    assert jkt == crypto.key_thumbprint(key)


def test_symmetric_alg_rejected():
    key = crypto.generate_ec_keypair()
    good = dpop.create_proof(key, HTM, HTU)
    header_b64, rest = good.split(".", 1)
    tampered_header = crypto.b64u_encode(b'{"typ":"dpop+jwt","alg":"none","jwk":{}}')
    with pytest.raises(dpop.InvalidProof):
        dpop.verify_proof(f"{tampered_header}.{rest}", htm=HTM, htu=HTU, replay_cache=_cache())
