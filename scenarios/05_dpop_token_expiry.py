"""Scenario 5 -- short-lived by design.

The access token is minted with a tiny TTL. Before it expires the client works;
after it expires the very same token is refused and the client simply asks for a
new one. Whatever an attacker manages to capture is only useful for a few
seconds -- contrast scenario 1, where the static key had no expiry at all.
"""

from __future__ import annotations

import time

import anyio

from _harness import Reporter, Server, settings_for

from aaif_ap2_demo.client_auth import DPoPAuth, obtain_token
from aaif_ap2_demo.crypto import generate_ec_keypair
from aaif_ap2_demo.mcp_client import AuthRejected, call_tool

TTL = 2


async def _body(port: int, rep: Reporter) -> None:
    settings = settings_for(port)
    key = generate_ec_keypair()

    token = (await obtain_token(settings.token_url, key))["access_token"]
    auth = DPoPAuth(key, token)

    before = await call_tool(settings, "whoami", {}, mode="dpop", auth=auth)
    rep.check(
        "token works inside its TTL",
        expected="whoami ok",
        got=f"is_error={before['is_error']}",
        passed=not before["is_error"],
    )

    wait = TTL + 2
    rep.step(f"sleeping {wait}s so the token is unambiguously expired")
    time.sleep(wait)

    got = "no rejection (BAD)"
    passed = False
    try:
        await call_tool(settings, "whoami", {}, mode="dpop", auth=DPoPAuth(key, token))
    except AuthRejected as exc:
        got = f"{exc.status} {exc.code}: {exc.description}"
        passed = exc.code == "invalid_token" and "expired" in exc.description
    rep.check("the same token is refused once expired", expected="401 invalid_token (expired)", got=got, passed=passed)

    fresh = (await obtain_token(settings.token_url, key))["access_token"]
    after = await call_tool(settings, "whoami", {}, mode="dpop", auth=DPoPAuth(key, fresh))
    rep.check(
        "re-minting a token restores access",
        expected="whoami ok again",
        got=f"is_error={after['is_error']}",
        passed=not after["is_error"],
    )


def main() -> int:
    rep = Reporter("05 dpop token expiry: seconds-wide blast radius")
    with Server(mode="dpop", env={"DPOP_ACCESS_TOKEN_TTL": str(TTL)}) as srv:
        anyio.run(_body, srv.port, rep)
    return rep.done()


if __name__ == "__main__":
    raise SystemExit(main())
