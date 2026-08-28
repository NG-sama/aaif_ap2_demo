# aaif_ap2_demo — DPoP proof-of-possession vs. a static bearer key, on a toy MCP server

A small prototype for the "Go Deeper" checkbox in a personal note on agent
identity and authorization:

> Try a small prototype: add short-lived token issuance (DPoP-style) to a toy MCP
> server you control, just to feel the mechanics of proof-of-possession vs. a
> static bearer key.

The **same** toy MCP payments server runs in one of two modes:

- `bearer` — accepts a static API key (the status quo the note criticises)
- `dpop` — issues short-lived access tokens bound to a client key thumbprint,
  and requires a fresh per-request DPoP proof (RFC 9449)

Five runnable scenarios show the difference. Domain: **payments**, an AP2-flavoured
toy (`get_balance`, `create_cart`, `authorize_payment`, `whoami`).

## Quickstart

```bash
uv sync

# run every scenario, boots its own server per scenario
uv run python scenarios/run_all.py

# unit tests (crypto / dpop / tokens, incl. an RFC 9449 known-answer)
uv run pytest -q
```

Poke at it by hand — `call` / `list-tools` need `serve` running in **another
terminal** (they exit with `error: cannot reach ...` otherwise):

```bash
# terminal 1 — DPoP mode (leave this running)
uv run dpop-demo serve --mode dpop --port 8080

# terminal 2
uv run dpop-demo call whoami --mode dpop --port 8080
uv run dpop-demo call create_cart --mode dpop --port 8080 --json '{"items":[{"sku":"book","price":12,"qty":2}]}'
uv run dpop-demo call authorize_payment --mode dpop --port 8080 --json '{"cart_id":"<id from above>","max_amount":50}'
cat audit.log        # jkt recorded per call

# stop terminal 1, restart in the other mode — note the principal collapses to "static"
uv run dpop-demo serve --mode bearer --port 8080
uv run dpop-demo call whoami --mode bearer --port 8080
```

`--port` defaults to 8080; `DPOP_PORT` / `DPOP_BASE_URL` work too.

## The five scenarios

| # | Name | Mode | Shows |
|---|---|---|---|
| 1 | `01_static_bearer_replay` | bearer | a copied static key authorizes payments from any host, forever; the log can't tell attacker from user |
| 2 | `02_dpop_happy_path` | dpop | keypair → `/token` (nonce challenge) → tool calls; receipt names the authorizing `jkt` |
| 3 | `03_dpop_stolen_token` | dpop | stolen access token + attacker's own key → `401 invalid_token` (thumbprint mismatch) |
| 4 | `04_dpop_replayed_proof` | dpop | replayed proof → `401 invalid_dpop_proof` (jti replay); proof reused on another route → `htu` mismatch |
| 5 | `05_dpop_token_expiry` | dpop | the same token stops working seconds later; re-mint to continue |

## Layout

```
src/aaif_ap2_demo/
  crypto.py          ES256 JWS, JWK, RFC 7638 thumbprint, ath hash   (hand-rolled on `cryptography`)
  dpop.py            create / verify a DPoP proof (RFC 9449)
  tokens.py          toy Authorization Server: mint / verify key-bound access tokens
  replay_cache.py    jti seen-set
  nonce.py           rotating server DPoP-Nonce
  auth_middleware.py ASGI middleware guarding /mcp: bearer | dpop
  server.py          MCPServer + /token + /.well-known, wired into one ASGI app
  client_auth.py     httpx2.Auth: fresh proof per request, nonce retry
  mcp_client.py      connect over Streamable HTTP; raw_mcp_request for attacker probes
  cli.py             `dpop-demo serve | call | list-tools`
scenarios/           the five scripts + run_all.py + _harness.py
tests/               pytest
docs/                architecture.md · dpop-vs-bearer.md · threat-model.md · references.md
```

## Environment knobs

| Var | Default | Meaning |
|---|---|---|
| `DPOP_MODE` | `dpop` | `bearer` or `dpop` |
| `DPOP_PORT` | `8080` | server port |
| `DPOP_ACCESS_TOKEN_TTL` | `30` | access-token lifetime, seconds |
| `DPOP_PROOF_LEEWAY` | `60` | accepted `iat` skew / replay-cache retention |
| `DPOP_REQUIRE_NONCE` | `1` | issue a `DPoP-Nonce` challenge before accepting proofs |
| `DEMO_STATIC_API_KEY` | `toy-static-key-do-not-use` | the `bearer`-mode secret |
| `DPOP_BASE_URL` | `http://127.0.0.1:$PORT` | overrides the token `aud` / proof `htu` base |

## Not production

Plain PEM keys in `.dev-keys/`, in-process replay cache and nonce store, no
client auth at `/token`, no TLS, no revocation list. It is a bench model for the
mechanism, not a library. See `docs/threat-model.md`.
