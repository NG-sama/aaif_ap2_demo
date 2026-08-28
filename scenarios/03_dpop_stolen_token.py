"""Scenario 3 -- stolen access token, no private key.

The attacker captures the ``Authorization: DPoP <token>`` value (a proxy log, an
SSRF, a leaked env var) but never had the client's private key. They mint their
own proof with their own key. The resource server checks the proof key's
thumbprint against the token's ``cnf.jkt`` and rejects: possession not proven.
"""

from __future__ import annotations

import anyio

from _harness import Reporter, Server, settings_for

from aaif_ap2_demo.client_auth import DPoPAuth, obtain_token
from aaif_ap2_demo.crypto import generate_ec_keypair
from aaif_ap2_demo.mcp_client import AuthRejected, call_tool, raw_mcp_request


async def _body(port: int, rep: Reporter) -> None:
    settings = settings_for(port)

    victim_key = generate_ec_keypair()
    token = (await obtain_token(settings.token_url, victim_key))["access_token"]

    rep.step("control: victim uses the token WITH its own key")
    ok = await call_tool(settings, "whoami", {}, mode="dpop", auth=DPoPAuth(victim_key, token))
    rep.check(
        "legitimate holder is accepted",
        expected="whoami returns auth=dpop",
        got=f"is_error={ok['is_error']}, auth={ok.get('structured', {}).get('auth')}",
        passed=not ok["is_error"] and ok["structured"]["auth"] == "dpop",
    )

    rep.step("attack: same token, attacker's freshly generated key")
    attacker_key = generate_ec_keypair()
    got = "no rejection (BAD)"
    passed = False
    try:
        await call_tool(settings, "whoami", {}, mode="dpop", auth=DPoPAuth(attacker_key, token))
    except AuthRejected as exc:
        got = f"{exc.status} {exc.code}: {exc.description}"
        passed = exc.code == "invalid_token"

    # also show the raw 401 for completeness
    raw = await raw_mcp_request(settings, auth=DPoPAuth(attacker_key, token))

    rep.check(
        "stolen token + wrong key is rejected at the binding check",
        expected="401 invalid_token (cnf.jkt != proof jkt)",
        got=f"{got} | raw status {raw.status_code}",
        passed=passed and raw.status_code == 401,
    )


def main() -> int:
    rep = Reporter("03 dpop stolen token: inert without the private key")
    with Server(mode="dpop") as srv:
        anyio.run(_body, srv.port, rep)
    return rep.done()


if __name__ == "__main__":
    raise SystemExit(main())
