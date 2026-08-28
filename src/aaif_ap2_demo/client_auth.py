"""Client-side auth for httpx2: a ``DPoP`` flow and a plain ``Bearer`` flow.

``DPoPAuth`` mints a *fresh* proof for every outgoing request (each MCP
JSON-RPC message is its own HTTP POST, so each gets its own proof), binds it to
the access token via ``ath``, and transparently answers a
``401 use_dpop_nonce`` challenge by retrying once with the server's nonce.

``BearerAuth`` just pins one static header on every request forever -- the
behaviour the prototype is contrasting against.
"""

from __future__ import annotations

import httpx2
from cryptography.hazmat.primitives.asymmetric import ec

from . import dpop


class BearerAuth(httpx2.Auth):
    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    def auth_flow(self, request):
        request.headers["Authorization"] = f"Bearer {self._api_key}"
        yield request


class DPoPAuth(httpx2.Auth):
    def __init__(self, key: ec.EllipticCurvePrivateKey, access_token: str, nonce: str | None = None) -> None:
        self.key = key
        self.access_token = access_token
        self.nonce = nonce

    def _apply(self, request) -> None:
        proof = dpop.create_proof(
            self.key,
            request.method,
            str(request.url),
            nonce=self.nonce,
            access_token=self.access_token,
        )
        request.headers["Authorization"] = f"DPoP {self.access_token}"
        request.headers["DPoP"] = proof

    def auth_flow(self, request):
        self._apply(request)
        response = yield request

        if response.status_code == 401 and response.headers.get("dpop-nonce"):
            # RFC 9449 section 8: adopt the server nonce and retry once.
            self.nonce = response.headers["dpop-nonce"]
            self._apply(request)
            yield request


async def obtain_token(
    token_url: str,
    key: ec.EllipticCurvePrivateKey,
    *,
    client_id: str = "toy-agent",
    scope: str = "payments:read payments:write",
    max_attempts: int = 3,
) -> dict:
    """Run the toy token-endpoint dance, including the nonce challenge.

    Returns the parsed token response ``{"access_token", "expires_in", ...}``.
    """
    nonce: str | None = None
    async with httpx2.AsyncClient(timeout=15) as client:
        for _ in range(max_attempts):
            proof = dpop.create_proof(key, "POST", token_url, nonce=nonce)
            resp = await client.post(
                token_url,
                json={"client_id": client_id, "scope": scope},
                headers={"DPoP": proof},
            )
            if resp.status_code == 401 and resp.headers.get("dpop-nonce"):
                nonce = resp.headers["dpop-nonce"]
                continue
            resp.raise_for_status()
            return resp.json()
    raise RuntimeError("token endpoint kept challenging for a nonce")
