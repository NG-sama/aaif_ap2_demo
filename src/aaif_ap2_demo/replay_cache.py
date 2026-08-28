"""A tiny in-memory ``jti`` seen-cache.

A DPoP proof carries a unique ``jti``. The resource server must reject a proof
whose ``jti`` it has already seen inside the acceptance window, which is what
stops a captured proof from being replayed verbatim (RFC 9449 section 11.1).
An in-process dict is fine for a single-node toy; production would use a shared
store (Redis) keyed on ``jti`` with the same TTL as the ``iat`` window.
"""

from __future__ import annotations

import time


class ReplayError(ValueError):
    """This jti has already been used within the acceptance window."""


class SeenJTICache:
    def __init__(self, ttl_seconds: int) -> None:
        self._ttl = ttl_seconds
        self._seen: dict[str, float] = {}

    def _prune(self, now: float) -> None:
        expired = [jti for jti, exp in self._seen.items() if exp <= now]
        for jti in expired:
            del self._seen[jti]

    def check_and_add(self, jti: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        self._prune(now)
        if jti in self._seen:
            raise ReplayError(f"replayed jti {jti!r}")
        self._seen[jti] = now + self._ttl

    def __len__(self) -> int:  # handy for assertions in tests
        return len(self._seen)
