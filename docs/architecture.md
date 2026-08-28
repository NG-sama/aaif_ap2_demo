# Architecture

Everything runs in one process behind one ASGI app. The only moving parts are:

| Piece | File | Job |
|---|---|---|
| Token endpoint (`POST /token`) | `server.py` `_token_route` | Toy Authorization Server. Verifies a DPoP proof, mints a short-lived access token bound to the proof key's thumbprint. |
| Auth middleware | `auth_middleware.py` | Wraps `/mcp`. Enforces `bearer` **or** `dpop`. On success injects an `x-mcp-principal` header the tools read. |
| MCP server | `server.py` `build_mcp` | `MCPServer` (the mcp 2.x class formerly called `FastMCP`) exposing four payments tools over Streamable HTTP. |
| Crypto core | `crypto.py`, `dpop.py`, `tokens.py` | JWS/ES256, JWK + RFC 7638 thumbprint, DPoP proof create/verify, access-token mint/verify. Hand-rolled on `cryptography` so the wire format is visible. |
| Replay cache / nonce | `replay_cache.py`, `nonce.py` | `jti` seen-set; rotating server `DPoP-Nonce`. |
| Client | `client_auth.py`, `mcp_client.py` | `httpx2.Auth` implementations: fresh proof per request, automatic nonce retry. |

```mermaid
flowchart LR
    subgraph Client
      K[(private key)]
      A[DPoPAuth / BearerAuth\nhttpx2.Auth]
    end
    subgraph "ASGI app (one process)"
      T["POST /token\ntoy Authorization Server"]
      M[["DpopAuthMiddleware\nguards /mcp"]]
      S["MCPServer\nStreamable HTTP /mcp"]
      TOOLS{{"get_balance\ncreate_cart\nauthorize_payment\nwhoami"}}
      RC[(jti replay cache)]
      NM[(DPoP-Nonce)]
    end
    K --> A
    A -- "1 . DPoP proof" --> T
    T -- "access token\n(cnf.jkt = thumbprint)" --> A
    A -- "Authorization: DPoP <token>\nDPoP: <fresh proof>" --> M
    M <--> RC
    M <--> NM
    M -- "x-mcp-principal" --> S --> TOOLS
```

## Sequence — static bearer (`DPOP_MODE=bearer`)

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant M as DpopAuthMiddleware
    participant S as MCP tool
    C->>M: POST /mcp  Authorization: Bearer toy-static-key...
    M->>M: constant-time compare to DEMO_STATIC_API_KEY
    M->>S: forward + x-mcp-principal {auth:"bearer", client_id:"static"}
    S-->>C: result
    Note over C,M: the same header works forever, from anywhere,<br/>for every caller — nothing ties it to a request or an identity
```

## Sequence — DPoP (`DPOP_MODE=dpop`)

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (holds private key)
    participant T as POST /token (AS)
    participant M as DpopAuthMiddleware (RS)
    participant S as MCP tool

    C->>T: POST /token  DPoP: proof(htm=POST, htu=/token)
    T-->>C: 401 use_dpop_nonce  + DPoP-Nonce: n1
    C->>T: POST /token  DPoP: proof(..., nonce=n1)
    T->>T: verify proof, read jkt = thumbprint(proof.jwk)
    T-->>C: access_token { cnf.jkt = jkt, exp = now+TTL }

    C->>M: POST /mcp  Authorization: DPoP <token>  DPoP: proof(htm,htu,ath,nonce=n1,jti)
    M->>M: verify_access_token(token)  (sig, aud, exp)
    M->>M: verify_proof: sig vs proof.jwk, htm/htu, iat, jti unseen, ath == H(token), nonce
    M->>M: assert thumbprint(proof.jwk) == token.cnf.jkt   ← the binding
    M->>S: forward + x-mcp-principal { auth:"dpop", client_id, jkt, scope }
    S-->>C: result (receipt names jkt)

    Note over M: replay the same proof → jti in cache → 401 invalid_dpop_proof<br/>steal token, no key → thumbprint mismatch → 401 invalid_token<br/>wait out TTL → 401 invalid_token (expired)
```

## Where the principal comes from

The MCP server never re-does auth. The middleware resolves a principal and
passes it down as a request header; `server.py::_principal_from_ctx` reads it
via `ctx.headers` (mcp exposes the underlying Starlette request headers to
tools). `whoami` echoes it; `authorize_payment` embeds `jkt` in the signed
receipt, which is the "provable attribution" the source note asks for.

See [`dpop-vs-bearer.md`](./dpop-vs-bearer.md) for the property-by-property
comparison and [`threat-model.md`](./threat-model.md) for how the five
scenarios map to MCP-T1 and to AP2's Mandate model.
