"""Scenario 4 -- captured proof, replayed verbatim.

The attacker captures a whole valid request: the access token *and* a complete,
correctly signed ``DPoP`` proof header. Replaying the exact bytes fails two
different ways:

* same proof to the same endpoint  -> ``jti`` already in the replay cache
* proof minted for ``/mcp`` sent to ``/token`` -> ``htu`` binding mismatch

A proof authorizes exactly one method+URI, once.
"""

from __future__ import annotations

import anyio
import httpx2

from _harness import Reporter, Server, settings_for

from aaif_ap2_demo import dpop
from aaif_ap2_demo.client_auth import obtain_token
from aaif_ap2_demo.crypto import generate_ec_keypair

_MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
    "MCP-Protocol-Version": "2025-06-18",
}
_INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "x", "version": "0"}},
}


async def _server_nonce(client: httpx2.AsyncClient, url: str, token: str, key) -> str:
    """Send a valid-but-nonceless proof, read the DPoP-Nonce off the challenge."""
    nonceless = dpop.create_proof(key, "POST", url, access_token=token)
    resp = await client.post(
        url, json=_INIT, headers={**_MCP_HEADERS, "Authorization": f"DPoP {token}", "DPoP": nonceless}
    )
    assert resp.status_code == 401 and resp.headers.get("dpop-nonce"), resp.text
    return resp.headers["dpop-nonce"]


async def _body(port: int, rep: Reporter) -> None:
    settings = settings_for(port)
    key = generate_ec_keypair()
    token = (await obtain_token(settings.token_url, key))["access_token"]

    async with httpx2.AsyncClient(timeout=15) as client:
        nonce = await _server_nonce(client, settings.mcp_url, token, key)

        # A valid proof for POST /mcp -- the "captured" one.
        proof_a = dpop.create_proof(key, "POST", settings.mcp_url, nonce=nonce, access_token=token)
        hdr = {**_MCP_HEADERS, "Authorization": f"DPoP {token}", "DPoP": proof_a}

        first = await client.post(settings.mcp_url, json=_INIT, headers=hdr)
        rep.step(f"first use of the captured proof -> HTTP {first.status_code}")

        replay = await client.post(settings.mcp_url, json=_INIT, headers=hdr)
        replay_body = replay.json() if replay.headers.get("content-type", "").startswith("application/json") else {}

        rep.check(
            "verbatim replay of the same proof is refused",
            expected="first 200, replay 401 invalid_dpop_proof (replayed jti)",
            got=f"first={first.status_code}, replay={replay.status_code} {replay_body.get('error')}",
            passed=first.status_code == 200
            and replay.status_code == 401
            and replay_body.get("error") == "invalid_dpop_proof",
        )

        # Fresh proof, still bound to /mcp, presented at /token -> htu mismatch.
        proof_b = dpop.create_proof(key, "POST", settings.mcp_url, nonce=nonce, access_token=token)
        wrong_ep = await client.post(
            settings.token_url,
            json={"client_id": "toy-agent", "scope": "payments:read"},
            headers={"DPoP": proof_b},
        )
        wrong_body = wrong_ep.json()
        rep.check(
            "a proof minted for /mcp is refused at /token",
            expected="4xx invalid_dpop_proof (htu mismatch)",
            got=f"{wrong_ep.status_code} {wrong_body.get('error')}: {wrong_body.get('error_description')}",
            passed=wrong_ep.status_code in (400, 401) and wrong_body.get("error") == "invalid_dpop_proof",
        )


def main() -> int:
    rep = Reporter("04 dpop replayed proof: bound to one method+URI, used once")
    with Server(mode="dpop") as srv:
        anyio.run(_body, srv.port, rep)
    return rep.done()


if __name__ == "__main__":
    raise SystemExit(main())
