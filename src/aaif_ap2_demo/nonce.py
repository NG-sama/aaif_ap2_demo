"""Server-side DPoP nonce management (RFC 9449 section 8 / 9).

The resource server (and token endpoint) can demand that proofs include a
server-chosen ``nonce``. This lets the server pin the freshness window itself
instead of trusting the client's clock. The client learns the value from a
``DPoP-Nonce`` response header on a ``401 use_dpop_nonce`` challenge, then
retries.

We keep the current nonce plus the immediately previous one, so a proof that
was built moments before a rotation is still accepted.
"""

from __future__ import annotations

import secrets
import time


class NonceManager:
    def __init__(self, ttl_seconds: int = 300) -> None:
        self._ttl = ttl_seconds
        self._current = secrets.token_urlsafe(16)
        self._previous: str | None = None
        self._rotated_at = time.time()

    def _maybe_rotate(self, now: float) -> None:
        if now - self._rotated_at >= self._ttl:
            self._previous = self._current
            self._current = secrets.token_urlsafe(16)
            self._rotated_at = now

    def current(self, now: float | None = None) -> str:
        now = time.time() if now is None else now
        self._maybe_rotate(now)
        return self._current

    def accepts(self, value: str | None, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        self._maybe_rotate(now)
        return value is not None and value in {self._current, self._previous}
