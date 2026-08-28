# References

## Specs implemented (in miniature) here

- **RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP).**
  <https://datatracker.ietf.org/doc/html/rfc9449>
  The whole point of the prototype. Section 4 (proof structure: `htm`, `htu`,
  `iat`, `jti`, `ath`, `nonce`), section 6 (`cnf.jkt` binding on the access
  token), section 8–9 (the `DPoP-Nonce` challenge), section 11 (replay).
  → `dpop.py`, `tokens.py`, `auth_middleware.py`, `nonce.py`.
- **RFC 7638 — JSON Web Key (JWK) Thumbprint.**
  <https://datatracker.ietf.org/doc/html/rfc7638>
  The canonical-JSON SHA-256 that produces `jkt`. → `crypto.jwk_thumbprint`.
  Known-answer test uses the EC key from RFC 9449 §6.1.
- **RFC 7515 — JSON Web Signature** and **RFC 7519 — JSON Web Token.**
  <https://datatracker.ietf.org/doc/html/rfc7515> ·
  <https://datatracker.ietf.org/doc/html/rfc7519>
  Compact serialization, ES256. → `crypto.jws_sign` / `crypto.jws_verify`.
- **RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens.**
  <https://datatracker.ietf.org/doc/html/rfc9068>
  Shape of the access token (`iss`, `aud`, `exp`, `scope`, `cnf`, `typ:at+jwt`).
- **RFC 9700 — Best Current Practice for OAuth 2.0 Security.**
  <https://datatracker.ietf.org/doc/html/rfc9700>
  Cited in `MCP-Security.md`; §2.2 covers sender-constraining tokens (DPoP / mTLS)
  and why bearer tokens are a standing liability.
- **RFC 9728 — OAuth 2.0 Protected Resource Metadata.**
  <https://datatracker.ietf.org/doc/html/rfc9728>
  The `/.well-known/oauth-protected-resource` document (minimal toy version).

## Model Context Protocol

- **MCP roadmap** (the source of the note): <https://blog.modelcontextprotocol.io/posts/mcp-roadmap/>
  — "Agent Identity & Enterprise Security" workstream names DPoP + Workload
  Identity Federation explicitly.
- **MCP Authorization specification**: <https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization>
- **MCP Python SDK** (`mcp` 2.x, `MCPServer` = the old `FastMCP`):
  <https://github.com/modelcontextprotocol/python-sdk>

## Context from personal notes

- *Agent Identity and Authorization* — the personal note this prototype comes
  from. The "three failure modes" table and the AP2 Mandate model.
- *MCP-Security* — notes on CoSAI WS4, MCP-T1..T12.
  <https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md>
- *WS4 secure agentic design* — MCP-T1 in the top-12; "strong agent identity" as
  the control.
- *MCP tools 101* — MCP tool/transport basics.

## Adjacent, referenced by the note (not implemented here)

- **Google AP2** — Agent Payments Protocol: <https://goo.gle/ap2> · Intent
  Mandate / Cart Mandate schemas.
- **Okta Agent SSO** — short-lived tokens for agents as first-class directory
  identities.
- **Cloudflare MCP Portal / WriteGuard** — risk-tiered policy layer in front of
  MCP servers: <https://blog.cloudflare.com/mcp-portal-writeguard-private-beta/>
