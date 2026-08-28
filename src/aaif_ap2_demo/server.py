"""The toy MCP payments server + the toy token endpoint, in one ASGI app.

Routes
------
``POST /token``   -- DPoP token endpoint. Client sends a ``DPoP`` proof header
                     (``htm=POST``, ``htu`` = this URL, no ``ath``) and a JSON
                     body ``{"client_id", "scope"}``. Issues a short-lived
                     access token bound to the proof key's thumbprint.
``GET  /``        -- human-readable description of the active mode.
``GET  /.well-known/oauth-protected-resource`` -- minimal RFC 9728-ish metadata.
``ANY  /mcp``     -- the MCP Streamable-HTTP endpoint, guarded by
                     :class:`DpopAuthMiddleware`.

Payments tools (an AP2-flavoured toy)
------------------------------------
``get_balance``       read            (needs ``payments:read``)
``create_cart``       prepare         (needs ``payments:read``) -- freezes items
                                      + price and hashes them: a "Cart Mandate"
                                      analogue.
``authorize_payment`` consequential   (needs ``payments:write``) -- returns a
                                      signed receipt naming the principal.
``whoami``            read            -- echoes the resolved principal.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from mcp.server.mcpserver import Context, MCPServer
from starlette.requests import Request
from starlette.responses import JSONResponse

from . import crypto, dpop
from .audit import append_event
from .auth_middleware import AuthState, DpopAuthMiddleware, decode_principal
from .config import (
    DEV_KEYS_DIR,
    ERR_INVALID_DPOP_PROOF,
    ERR_USE_DPOP_NONCE,
    READ_SCOPE,
    WRITE_SCOPE,
    Settings,
    load_settings,
)
from .tokens import mint_access_token

# ------------------------------------------------------------------------- #
# A pretend ledger. Accounts, balances, and carts live in memory.
# ------------------------------------------------------------------------- #
_BALANCES: dict[str, float] = {"acct-alice": 250.00, "acct-merchant": 0.0}
_CARTS: dict[str, dict[str, Any]] = {}
_RECEIPTS: list[dict[str, Any]] = []


class ToolAuthError(Exception):
    """Raised inside a tool when the principal lacks the required scope."""


def _principal_from_ctx(ctx: Context) -> dict[str, Any]:
    headers = ctx.headers or {}
    principal = decode_principal(headers.get("x-mcp-principal"))
    if principal is None:
        raise ToolAuthError("no authenticated principal on this request")
    return principal


def _require_scope(principal: dict[str, Any], scope: str) -> None:
    granted = set(str(principal.get("scope", "")).split())
    if scope not in granted:
        raise ToolAuthError(f"principal is missing required scope {scope!r}")


def _receipt_signing_key() -> ec.EllipticCurvePrivateKey:
    return crypto.load_or_create_private_key(DEV_KEYS_DIR / "rs_receipt_key.pem")


# ------------------------------------------------------------------------- #
def build_mcp(settings: Settings) -> MCPServer:
    mcp: MCPServer = MCPServer(
        "ap2-toy-payments",
        instructions="Toy payments tools for the DPoP vs. bearer prototype.",
    )

    @mcp.tool(description="Return the balance of an account (needs payments:read).")
    def get_balance(account: str, ctx: Context) -> dict[str, Any]:
        try:
            principal = _principal_from_ctx(ctx)
            _require_scope(principal, READ_SCOPE)
        except ToolAuthError as exc:
            return {"error": str(exc)}
        result = {"account": account, "balance": _BALANCES.get(account), "currency": "USD"}
        append_event(tool="get_balance", principal=principal, arguments={"account": account}, result=result)
        return result

    @mcp.tool(
        description="Freeze a set of line items into a cart and hash them "
        "(a 'Cart Mandate' analogue). Needs payments:read."
    )
    def create_cart(items: list[dict[str, Any]], ctx: Context) -> dict[str, Any]:
        try:
            principal = _principal_from_ctx(ctx)
            _require_scope(principal, READ_SCOPE)
        except ToolAuthError as exc:
            return {"error": str(exc)}
        total = round(sum(float(i["price"]) * int(i.get("qty", 1)) for i in items), 2)
        frozen = json.dumps(items, separators=(",", ":"), sort_keys=True)
        cart_id = "cart-" + hashlib.sha256(f"{time.time()}{frozen}".encode()).hexdigest()[:12]
        cart = {
            "cart_id": cart_id,
            "items": items,
            "total": total,
            "currency": "USD",
            "items_hash": crypto.b64u_encode(hashlib.sha256(frozen.encode()).digest()),
            "created_at": int(time.time()),
        }
        _CARTS[cart_id] = cart
        append_event(tool="create_cart", principal=principal, arguments={"items": items}, result=cart)
        return cart

    @mcp.tool(
        description="Authorize payment for a cart, up to max_amount. Consequential: "
        "needs payments:write. Returns a signed receipt naming the caller."
    )
    def authorize_payment(cart_id: str, max_amount: float, ctx: Context) -> dict[str, Any]:
        try:
            principal = _principal_from_ctx(ctx)
            _require_scope(principal, WRITE_SCOPE)
        except ToolAuthError as exc:
            return {"error": str(exc)}
        cart = _CARTS.get(cart_id)
        if cart is None:
            return {"error": f"unknown cart {cart_id!r}"}
        if cart["total"] > max_amount:
            return {"error": f"cart total {cart['total']} exceeds max_amount {max_amount}"}

        _BALANCES["acct-alice"] = round(_BALANCES.get("acct-alice", 0.0) - cart["total"], 2)
        _BALANCES["acct-merchant"] = round(_BALANCES.get("acct-merchant", 0.0) + cart["total"], 2)

        payload = {
            "cart_id": cart_id,
            "amount": cart["total"],
            "currency": "USD",
            "items_hash": cart["items_hash"],
            "authorized_by": {
                "auth": principal.get("auth"),
                "client_id": principal.get("client_id"),
                # In dpop mode this names the exact key that proved possession.
                "jkt": principal.get("jkt"),
                "proof_of_possession": principal.get("auth") == "dpop",
            },
            "authorized_at": int(time.time()),
        }
        receipt_jws = crypto.jws_sign({"typ": "receipt+jws", "alg": crypto.JOSE_ALG}, payload, _receipt_signing_key())
        receipt = {"receipt": payload, "receipt_jws": receipt_jws}
        _RECEIPTS.append(receipt)
        append_event(
            tool="authorize_payment",
            principal=principal,
            arguments={"cart_id": cart_id, "max_amount": max_amount},
            result=payload,
        )
        return receipt

    @mcp.tool(description="Echo the principal the server resolved for this call.")
    def whoami(ctx: Context) -> dict[str, Any]:
        try:
            principal = _principal_from_ctx(ctx)
        except ToolAuthError as exc:
            return {"error": str(exc)}
        append_event(tool="whoami", principal=principal, arguments={}, result=principal)
        return principal

    return mcp


# ------------------------------------------------------------------------- #
# Custom (unauthenticated) routes
# ------------------------------------------------------------------------- #
def _token_route(settings: Settings, state: AuthState):
    async def issue_token(request: Request) -> JSONResponse:
        proof = request.headers.get("dpop")
        if not proof:
            return _dpop_error(ERR_INVALID_DPOP_PROOF, "missing DPoP proof header", 400)

        current_nonce = state.nonces.current()
        try:
            body = await request.json()
        except Exception:
            body = {}
        client_id = str(body.get("client_id") or "toy-agent")
        scope = str(body.get("scope") or f"{READ_SCOPE} {WRITE_SCOPE}")

        try:
            jkt = dpop.verify_proof(
                proof,
                htm="POST",
                htu=settings.token_url,
                replay_cache=state.replay_cache,
                leeway=settings.proof_leeway,
                expected_ath=None,  # no access token presented at the token endpoint
                require_nonce=settings.require_nonce,
                current_nonce=current_nonce,
            )
        except dpop.UseDPoPNonce as exc:
            if settings.require_nonce and not state.nonces.accepts(_peek_nonce(proof)):
                return _dpop_error(ERR_USE_DPOP_NONCE, str(exc), 401, nonce=current_nonce)
            return _dpop_error(ERR_INVALID_DPOP_PROOF, str(exc), 400)
        except dpop.DPoPError as exc:
            return _dpop_error(exc.code, str(exc), 400)

        token = mint_access_token(
            jkt=jkt,
            client_id=client_id,
            scope=scope,
            audience=settings.mcp_url,
            issuer=settings.issuer,
            ttl_seconds=settings.access_token_ttl,
        )
        return JSONResponse(
            {
                "access_token": token,
                "token_type": "DPoP",
                "expires_in": settings.access_token_ttl,
                "scope": scope,
            }
        )

    return issue_token


def _index_route(settings: Settings):
    async def index(_: Request) -> JSONResponse:
        return JSONResponse(
            {
                "service": "ap2-toy-payments",
                "mode": settings.mode,
                "mcp_endpoint": settings.mcp_url,
                "token_endpoint": settings.token_url if settings.mode == "dpop" else None,
                "access_token_ttl": settings.access_token_ttl,
                "require_nonce": settings.require_nonce,
                "note": "bearer mode accepts a static key; dpop mode requires proof-of-possession",
            }
        )

    return index


def _prm_route(settings: Settings):
    async def protected_resource_metadata(_: Request) -> JSONResponse:
        return JSONResponse(
            {
                "resource": settings.mcp_url,
                "authorization_servers": [settings.issuer],
                "bearer_methods_supported": ["header"],
                "dpop_signing_alg_values_supported": [crypto.JOSE_ALG],
            }
        )

    return protected_resource_metadata


def _dpop_error(code: str, description: str, status: int, *, nonce: str | None = None) -> JSONResponse:
    headers = {"WWW-Authenticate": f'DPoP error="{code}", error_description="{description}"'}
    if nonce is not None:
        headers["DPoP-Nonce"] = nonce
    return JSONResponse({"error": code, "error_description": description}, status_code=status, headers=headers)


def _peek_nonce(proof: str) -> str | None:
    try:
        return json.loads(crypto.b64u_decode(proof.split(".")[1])).get("nonce")
    except Exception:
        return None


# ------------------------------------------------------------------------- #
def build_app(settings: Settings | None = None):
    settings = settings or load_settings()
    state = AuthState(settings)
    mcp = build_mcp(settings)

    if settings.mode == "dpop":
        mcp.custom_route("/token", methods=["POST"])(_token_route(settings, state))
    mcp.custom_route("/", methods=["GET"])(_index_route(settings))
    mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])(_prm_route(settings))

    inner = mcp.streamable_http_app(streamable_http_path="/mcp", host=settings.host)
    return DpopAuthMiddleware(inner, settings, state)


def serve(settings: Settings | None = None) -> None:
    import uvicorn

    settings = settings or load_settings()
    uvicorn.run(build_app(settings), host=settings.host, port=settings.port, log_level="warning")


if __name__ == "__main__":  # pragma: no cover
    serve()
