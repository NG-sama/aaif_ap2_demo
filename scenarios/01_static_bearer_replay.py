"""Scenario 1 -- the problem.

Server in ``bearer`` mode. A legitimate client authorizes a payment with the
static API key. An "attacker" process that merely copied that key (from a log, a
config file, a proxy capture) replays it from scratch and succeeds: it moves
money and the audit trail cannot tell the two apart. This is MCP-T1
("improper authentication & identity") in one screen.
"""

from __future__ import annotations

import anyio

from _harness import Reporter, Server, settings_for

from aaif_ap2_demo.client_auth import BearerAuth
from aaif_ap2_demo.mcp_client import call_tool


async def _body(port: int, rep: Reporter) -> None:
    settings = settings_for(port)
    stolen_key = settings.static_api_key  # the "capture"

    rep.step("legit client: create cart + authorize_payment with the static key")
    cart = await call_tool(settings, "create_cart", {"items": [{"sku": "book", "price": 12.0}]}, mode="bearer")
    cart_id = cart["structured"]["cart_id"]
    legit = await call_tool(settings, "authorize_payment", {"cart_id": cart_id, "max_amount": 50}, mode="bearer")
    legit_ok = not legit["is_error"] and "receipt" in legit.get("structured", {})

    rep.step("attacker: brand-new client, only the copied key, replays authorize_payment")
    cart2 = await call_tool(
        settings,
        "create_cart",
        {"items": [{"sku": "gpu", "price": 40.0}]},
        mode="bearer",
        auth=BearerAuth(stolen_key),
    )
    cart2_id = cart2["structured"]["cart_id"]
    attack = await call_tool(
        settings,
        "authorize_payment",
        {"cart_id": cart2_id, "max_amount": 50},
        mode="bearer",
        auth=BearerAuth(stolen_key),
    )
    attack_ok = not attack["is_error"] and "receipt" in attack.get("structured", {})

    who_legit = legit["structured"]["receipt"]["authorized_by"]
    who_attack = attack["structured"]["receipt"]["authorized_by"]

    rep.check(
        "stolen static key still authorizes a payment",
        expected="attacker payment SUCCEEDS (this is the weakness)",
        got=f"legit_ok={legit_ok}, attacker_ok={attack_ok}",
        passed=legit_ok and attack_ok,
    )
    rep.check(
        "audit trail cannot attribute the action",
        expected="legit and attacker principals are identical / no key identity",
        got=f"{who_legit} vs {who_attack}",
        passed=who_legit == who_attack and who_attack.get("jkt") is None,
    )


def main() -> int:
    rep = Reporter("01 static bearer key: capture-and-replay succeeds")
    with Server(mode="bearer") as srv:
        anyio.run(_body, srv.port, rep)
    return rep.done()


if __name__ == "__main__":
    raise SystemExit(main())
