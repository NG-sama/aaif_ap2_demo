"""Scenario 2 -- the legitimate DPoP flow, end to end.

Generate a keypair, obtain a short-lived access token from ``/token`` (the
server issues a DPoP-Nonce challenge first; the client retries automatically),
then call the payments tools. Each MCP call carries its own fresh proof. The
receipt names the exact key (``jkt``) that proved possession.
"""

from __future__ import annotations

import anyio

from _harness import Reporter, Server, settings_for

from aaif_ap2_demo.client_auth import DPoPAuth, obtain_token
from aaif_ap2_demo.crypto import generate_ec_keypair, key_thumbprint
from aaif_ap2_demo.mcp_client import call_tool


async def _body(port: int, rep: Reporter) -> None:
    settings = settings_for(port)
    key = generate_ec_keypair()
    my_jkt = key_thumbprint(key)

    rep.step("POST /token with a DPoP proof (nonce challenge handled transparently)")
    token = await obtain_token(settings.token_url, key)
    rep.step(f"got access_token, expires_in={token['expires_in']}s, bound to jkt={my_jkt[:12]}...")

    auth = DPoPAuth(key, token["access_token"])
    bal = await call_tool(settings, "get_balance", {"account": "acct-alice"}, mode="dpop", auth=auth)
    cart = await call_tool(
        settings, "create_cart", {"items": [{"sku": "sub", "price": 9.0, "qty": 3}]}, mode="dpop", auth=auth
    )
    cart_id = cart["structured"]["cart_id"]
    receipt = await call_tool(
        settings, "authorize_payment", {"cart_id": cart_id, "max_amount": 50}, mode="dpop", auth=auth
    )

    authorized_by = receipt["structured"]["receipt"]["authorized_by"]
    rep.check(
        "tools succeed and the balance reads back",
        expected="get_balance ok, cart total 27.0",
        got=f"balance={bal['structured'].get('balance')}, cart_total={cart['structured'].get('total')}",
        passed=not bal["is_error"] and cart["structured"]["total"] == 27.0,
    )
    rep.check(
        "receipt cryptographically names the authorizing key",
        expected=f"proof_of_possession=True, jkt={my_jkt[:12]}...",
        got=f"proof_of_possession={authorized_by['proof_of_possession']}, jkt={str(authorized_by['jkt'])[:12]}...",
        passed=authorized_by["proof_of_possession"] and authorized_by["jkt"] == my_jkt,
    )


def main() -> int:
    rep = Reporter("02 dpop happy path: token issuance + per-request proof")
    with Server(mode="dpop") as srv:
        anyio.run(_body, srv.port, rep)
    return rep.done()


if __name__ == "__main__":
    raise SystemExit(main())
