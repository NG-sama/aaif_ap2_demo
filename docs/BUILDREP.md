# BuildRep — aaif_ap2_demo

Curated build log: pivots, decisions, milestones — in my own words.
The machine record of *what* happened lives in `entire`; this file is the *why*.

<!-- newest first -->

## 2026-08-28 — Milestone: DPoP-vs-bearer MCP prototype landed and published

**Type:** milestone
**Session:** entire:a75f6305-4f92-49e8-8054-72ef7a8ae329  ·  **Commit:** pending

### What changed
- New repo `aaif_ap2_demo`: one ASGI app = toy `/token` Authorization Server + `DpopAuthMiddleware` guarding `/mcp` + `MCPServer` (mcp 2.x) over Streamable HTTP, flippable via `DPOP_MODE=bearer|dpop`.
- Full DPoP mechanics by hand: `cnf.jkt` binding, per-request proof (`htm/htu/iat/jti/ath`), `DPoP-Nonce` challenge, `jti` replay cache.
- 5 narrated attacker scenarios + 20 pytest tests (incl. an RFC 9449 known-answer thumbprint), all green.
- Pre-publish privacy scrub, then first commit pushed to GitHub.

### Thinking
Chose the payments/AP2 domain so the "consequential action needs proof-of-possession" story has teeth — the signed receipt names the authorizing key. Went with the real mcp SDK over a hand-rolled JSON-RPC toy for fidelity; cost a detour when mcp 2.1.1 turned out to rename `FastMCP`→`MCPServer`, ship `httpx2`, and change the client transport signature. Hand-rolled the JWS/JWK/thumbprint crypto on `cryptography` instead of PyJWT so every wire byte is legible — the point is to *feel* the mechanism. Enforcement lives in ASGI middleware, not the MCP layer, so bearer and DPoP share one path and the principal reaches tools via an injected header.

### My notes
came across this article through my weekly AI engineering digest. came across the article for payments. The industry just moved from "can an agent call a tool" to "can we **prove, govern, and audit** who authorized that call." This week alone: Google's A2A protocol joined the Linux Foundation's new **Agentic AI Foundation (AAIF)** alongside MCP, MCP itself published a roadmap pivoting toward **agent identity as a first-class spec concern**, **Okta shipped Agent SSO**, **Cloudflare shipped WriteGuard**, and **Google's Agent Payments Protocol (AP2)** matured its cryptographic "mandate" model — all converging on the same problem: agents acting with delegated, provable, revocable authority instead of hardcoded API keys.

### Open threads
- In-process replay cache + nonce store; a multi-node RS needs a shared store (the note's "Workload Identity Federation" angle).
- No client auth at `/token`, no TLS, PEM keys on disk — bench model only.
- Could add an Intent-Mandate-style delegated flow (separate user vs. agent keys) to mirror AP2 more closely.
