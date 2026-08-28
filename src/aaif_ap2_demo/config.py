"""Runtime configuration, all overridable by environment variable.

The demo is deliberately tunable so the scenarios can shrink the access-token
TTL to a couple of seconds, flip the server between ``bearer`` and ``dpop``
enforcement, and point the client at an ephemeral port.

Every field is read through ``default_factory`` so a fresh ``Settings()`` picks
up environment changes made within the same process (the scenario harness relies
on this).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEV_KEYS_DIR = REPO_ROOT / ".dev-keys"
AUDIT_LOG_PATH = REPO_ROOT / "audit.log"

# RFC 9449 uses these exact tokens in the WWW-Authenticate / error responses.
ERR_INVALID_TOKEN = "invalid_token"
ERR_INVALID_DPOP_PROOF = "invalid_dpop_proof"
ERR_USE_DPOP_NONCE = "use_dpop_nonce"

READ_SCOPE = "payments:read"
WRITE_SCOPE = "payments:write"


def _s(name: str, default: str) -> str:
    return os.environ.get(name) or default


def _i(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw not in (None, "") else default


def _b(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw in (None, ""):
        return default
    return raw not in ("0", "false", "False", "no")


@dataclass
class Settings:
    # "bearer" -> static API key; "dpop" -> proof-of-possession (default).
    mode: str = field(default_factory=lambda: _s("DPOP_MODE", "dpop"))

    host: str = field(default_factory=lambda: _s("DPOP_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _i("DPOP_PORT", 8080))

    # Short-lived on purpose: this is the whole point of the prototype.
    access_token_ttl: int = field(default_factory=lambda: _i("DPOP_ACCESS_TOKEN_TTL", 30))

    # Clock-skew / freshness window for a DPoP proof's `iat`, and jti replay-cache
    # retention.
    proof_leeway: int = field(default_factory=lambda: _i("DPOP_PROOF_LEEWAY", 60))

    # The toy static credential, used only in `bearer` mode.
    static_api_key: str = field(default_factory=lambda: _s("DEMO_STATIC_API_KEY", "toy-static-key-do-not-use"))

    # Whether the server issues a DPoP-Nonce challenge before accepting proofs
    # (RFC 9449 section 8). On by default so the "full mechanics" path is exercised.
    require_nonce: bool = field(default_factory=lambda: _b("DPOP_REQUIRE_NONCE", True))

    issuer: str = field(default_factory=lambda: _s("DPOP_ISSUER", "https://toy-as.example"))

    _base_url_override: str | None = field(default_factory=lambda: os.environ.get("DPOP_BASE_URL"))

    @property
    def base_url(self) -> str:
        return self._base_url_override or f"http://{self.host}:{self.port}"

    @property
    def mcp_url(self) -> str:
        return f"{self.base_url}/mcp"

    @property
    def token_url(self) -> str:
        return f"{self.base_url}/token"


def load_settings() -> Settings:
    """Build a fresh Settings from the current environment."""
    return Settings()
