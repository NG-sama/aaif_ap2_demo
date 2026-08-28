"""A thin MCP client: connect over Streamable HTTP with the chosen auth, call a
tool (or list tools), return the result as plain dicts.

Also exposes ``raw_mcp_request`` -- a single hand-built POST to ``/mcp`` -- which
the attacker scenarios use to inspect exactly what the server's auth layer
returns (status, ``error`` code, ``DPoP-Nonce``) without the MCP SDK wrapping
failures in TaskGroup tracebacks.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import httpx2
from cryptography.hazmat.primitives.asymmetric import ec
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

from .client_auth import BearerAuth, DPoPAuth, obtain_token
from .config import DEV_KEYS_DIR, Settings
from .crypto import load_or_create_private_key

_MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
    "MCP-Protocol-Version": "2025-06-18",
}


class AuthRejected(Exception):
    """The server's auth layer returned a 401 before MCP could run."""

    def __init__(self, status: int, code: str, description: str, nonce: str | None = None) -> None:
        super().__init__(f"{status} {code}: {description}")
        self.status = status
        self.code = code
        self.description = description
        self.nonce = nonce


class ServerUnreachable(Exception):
    """Could not open a TCP connection to the demo server."""


def _contains_connect_error(exc: BaseException) -> bool:
    """True if ``exc`` (or anything it wraps / groups) is an httpx connect error."""
    seen: set[int] = set()
    stack: list[BaseException | None] = [exc]
    while stack:
        cur = stack.pop()
        if cur is None or id(cur) in seen:
            continue
        seen.add(id(cur))
        if isinstance(cur, (httpx2.ConnectError, httpx2.ConnectTimeout)):
            return True
        stack.append(cur.__cause__)
        stack.append(cur.__context__)
        stack.extend(getattr(cur, "exceptions", []) or [])
    return False


def load_client_key(name: str = "client_key.pem") -> ec.EllipticCurvePrivateKey:
    return load_or_create_private_key(DEV_KEYS_DIR / name)


def _initialize_body(request_id: int = 1) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "dpop-demo-probe", "version": "0"},
        },
    }


async def raw_mcp_request(
    settings: Settings,
    *,
    auth: httpx2.Auth | None = None,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
) -> httpx2.Response:
    """POST once to ``settings.mcp_url``. If ``auth`` is given it drives the
    DPoP/bearer flow (including a nonce retry); if ``headers`` is given those are
    sent verbatim (used to replay a captured proof)."""
    send_headers = dict(_MCP_HEADERS)
    send_headers.update(headers or {})
    async with httpx2.AsyncClient(timeout=15, auth=auth) as client:
        return await client.post(settings.mcp_url, json=body or _initialize_body(), headers=send_headers)


def _raise_if_401(resp: httpx2.Response) -> None:
    if resp.status_code != 401:
        return
    try:
        payload = resp.json()
    except Exception:
        payload = {}
    raise AuthRejected(
        401,
        payload.get("error", "unauthorized"),
        payload.get("error_description", resp.text[:200]),
        resp.headers.get("dpop-nonce"),
    )


@asynccontextmanager
async def open_session(
    settings: Settings,
    *,
    mode: str | None = None,
    auth: httpx2.Auth | None = None,
):
    """Yield an initialized ``ClientSession`` against ``settings.mcp_url``.

    On any failure, retry once as a raw POST so a 401 surfaces as a clean
    :class:`AuthRejected` instead of a nested TaskGroup traceback.
    """
    mode = mode or settings.mode
    hint = f"is `dpop-demo serve --mode {mode} --port {settings.port}` running?"
    try:
        if auth is None:
            if mode == "bearer":
                auth = BearerAuth(settings.static_api_key)
            else:
                key = load_client_key()
                token = await obtain_token(settings.token_url, key)
                auth = DPoPAuth(key, token["access_token"])

        http_client = httpx2.AsyncClient(auth=auth, timeout=30)
        async with http_client:
            async with streamable_http_client(settings.mcp_url, http_client=http_client) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    yield session
    except Exception as exc:  # includes the anyio ExceptionGroup from the task group
        if _contains_connect_error(exc):
            raise ServerUnreachable(f"cannot reach {settings.base_url} - {hint}") from exc
        try:
            probe = await raw_mcp_request(settings, auth=auth)
        except (httpx2.ConnectError, httpx2.ConnectTimeout):
            raise ServerUnreachable(f"cannot reach {settings.base_url} - {hint}") from exc
        _raise_if_401(probe)
        raise


def _result_to_dict(result: Any) -> dict[str, Any]:
    data = result.model_dump(mode="json", by_alias=True)
    out: dict[str, Any] = {"is_error": bool(data.get("isError"))}
    if data.get("structuredContent") is not None:
        out["structured"] = data["structuredContent"]
    text = [b.get("text") for b in data.get("content", []) if b.get("type") == "text"]
    if text:
        out["text"] = text if len(text) > 1 else text[0]
    return out


async def call_tool(
    settings: Settings,
    tool: str,
    arguments: dict[str, Any],
    *,
    mode: str | None = None,
    auth: httpx2.Auth | None = None,
) -> dict[str, Any]:
    async with open_session(settings, mode=mode, auth=auth) as session:
        result = await session.call_tool(tool, arguments)
    return _result_to_dict(result)


async def list_tools(
    settings: Settings,
    *,
    mode: str | None = None,
    auth: httpx2.Auth | None = None,
) -> list[str]:
    async with open_session(settings, mode=mode, auth=auth) as session:
        result = await session.list_tools()
    return [t.name for t in result.tools]
