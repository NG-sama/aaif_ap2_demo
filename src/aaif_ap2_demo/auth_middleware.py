"""ASGI middleware that enforces either a static bearer key or a DPoP
proof-of-possession on requests to the ``/mcp`` endpoint.

It runs *outside* the MCP Streamable-HTTP app. On success it resolves a
"principal" and forwards it to the tool layer by injecting an
``x-mcp-principal`` request header (the MCP server exposes request headers to
tools via ``ctx.headers``). On failure it returns an RFC 9449-shaped ``401``.
"""

from __future__ import annotations

import json
from typing import Any

from . import crypto, dpop
from .config import (
    ERR_INVALID_DPOP_PROOF,
    ERR_INVALID_TOKEN,
    ERR_USE_DPOP_NONCE,
    Settings,
)
from dataclasses import dataclass, field

from .nonce import NonceManager
from .replay_cache import SeenJTICache
from .tokens import TokenError, verify_access_token

PRINCIPAL_HEADER = b"x-mcp-principal"
GUARDED_PATHS = {"/mcp"}


@dataclass
class AuthState:
    """Replay cache + nonce manager, shared between the middleware (guarding
    ``/mcp``) and the ``/token`` endpoint so both speak about the same nonces."""

    settings: Settings
    replay_cache: SeenJTICache = field(init=False)
    nonces: NonceManager = field(init=False)

    def __post_init__(self) -> None:
        self.replay_cache = SeenJTICache(ttl_seconds=max(self.settings.proof_leeway * 2, 120))
        self.nonces = NonceManager()


def encode_principal(principal: dict[str, Any]) -> str:
    return crypto.b64u_encode(json.dumps(principal).encode("utf-8"))


def decode_principal(value: str | None) -> dict[str, Any] | None:
    if not value:
        return None
    try:
        return json.loads(crypto.b64u_decode(value))
    except Exception:
        return None


class AuthError(Exception):
    def __init__(self, code: str, description: str, *, nonce: str | None = None) -> None:
        super().__init__(description)
        self.code = code
        self.description = description
        self.nonce = nonce


class DpopAuthMiddleware:
    def __init__(self, app, settings: Settings, state: AuthState) -> None:
        self.app = app
        self.settings = settings
        self.replay_cache = state.replay_cache
        self.nonces = state.nonces

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or scope.get("path") not in GUARDED_PATHS:
            await self.app(scope, receive, send)
            return

        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        try:
            principal = self._authenticate(scope, headers)
        except AuthError as exc:
            await self._send_401(send, exc)
            return

        # Forward the resolved principal to the tool layer via a header.
        new_headers = [
            (k, v) for k, v in scope.get("headers", []) if k.lower() != PRINCIPAL_HEADER
        ]
        new_headers.append((PRINCIPAL_HEADER, encode_principal(principal).encode()))
        await self.app({**scope, "headers": new_headers}, receive, send)

    # ------------------------------------------------------------------ #
    def _authenticate(self, scope, headers: dict[str, str]) -> dict[str, Any]:
        authz = headers.get("authorization", "")
        scheme, _, credential = authz.partition(" ")
        scheme = scheme.lower()

        if self.settings.mode == "bearer":
            if scheme != "bearer" or credential != self.settings.static_api_key:
                raise AuthError(ERR_INVALID_TOKEN, "bad or missing static bearer key")
            # Every caller collapses to the same identity: the core weakness.
            return {"auth": "bearer", "client_id": "static", "scope": "payments:read payments:write"}

        # ---- dpop mode ----
        if scheme != "dpop":
            raise AuthError(ERR_INVALID_TOKEN, "expected `Authorization: DPoP <token>`")
        proof = headers.get("dpop")
        if not proof:
            raise AuthError(ERR_INVALID_DPOP_PROOF, "missing DPoP proof header")

        try:
            claims = verify_access_token(credential, audience=self.settings.mcp_url)
        except TokenError as exc:
            raise AuthError(ERR_INVALID_TOKEN, str(exc)) from exc

        htu = self._reconstruct_url(scope, headers)
        current_nonce = self.nonces.current()
        try:
            jkt = dpop.verify_proof(
                proof,
                htm=scope["method"],
                htu=htu,
                replay_cache=self.replay_cache,
                leeway=self.settings.proof_leeway,
                expected_ath=crypto.access_token_hash(credential),
                require_nonce=self.settings.require_nonce,
                current_nonce=current_nonce,
            )
        except dpop.UseDPoPNonce as exc:
            # Only challenge if the presented nonce is not one we still accept.
            proof_nonce = _safe_proof_nonce(proof)
            if self.settings.require_nonce and not self.nonces.accepts(proof_nonce):
                raise AuthError(ERR_USE_DPOP_NONCE, str(exc), nonce=current_nonce) from exc
            raise AuthError(ERR_INVALID_DPOP_PROOF, str(exc)) from exc
        except dpop.DPoPError as exc:
            raise AuthError(exc.code, str(exc)) from exc

        # The binding check: the proof key must be the key the token was issued to.
        if jkt != claims["cnf"]["jkt"]:
            raise AuthError(
                ERR_INVALID_TOKEN,
                "access token is bound to a different key (cnf.jkt != proof jkt)",
            )

        return {
            "auth": "dpop",
            "client_id": claims["sub"],
            "jkt": jkt,
            "scope": claims.get("scope", ""),
            "token_jti": claims.get("jti"),
            "token_exp": claims.get("exp"),
        }

    @staticmethod
    def _reconstruct_url(scope, headers: dict[str, str]) -> str:
        scheme = headers.get("x-forwarded-proto") or scope.get("scheme", "http")
        host = headers.get("host") or "localhost"
        return f"{scheme}://{host}{scope['path']}"

    async def _send_401(self, send, exc: AuthError) -> None:
        params = [f'error="{exc.code}"', f'error_description="{exc.description}"']
        resp_headers = [
            (b"content-type", b"application/json"),
            (b"www-authenticate", ("DPoP " + ", ".join(params)).encode()),
        ]
        if exc.nonce is not None:
            resp_headers.append((b"dpop-nonce", exc.nonce.encode()))
        body = json.dumps({"error": exc.code, "error_description": exc.description}).encode()
        await send({"type": "http.response.start", "status": 401, "headers": resp_headers})
        await send({"type": "http.response.body", "body": body})


def _safe_proof_nonce(proof: str) -> str | None:
    try:
        _, payload = proof.split(".")[0], json.loads(crypto.b64u_decode(proof.split(".")[1]))
        return payload.get("nonce")
    except Exception:
        return None
