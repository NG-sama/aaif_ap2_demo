"""Append-only JSONL audit trail.

The note this prototype comes from names "no attribution" as the first failure
mode of static keys: you cannot tell from a log *which* agent, holding *which*
credential, did a thing. Here every tool call writes a line that records the
resolved principal. In ``dpop`` mode that includes the key thumbprint (``jkt``);
in ``bearer`` mode the principal is literally ``"static"`` for every caller,
which is the point.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .config import AUDIT_LOG_PATH


def append_event(
    *,
    tool: str,
    principal: dict[str, Any],
    arguments: dict[str, Any],
    result: dict[str, Any],
    path: Path | None = None,
) -> None:
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tool": tool,
        "principal": principal,
        "arguments": arguments,
        "result": result,
    }
    target = path or AUDIT_LOG_PATH
    with target.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, separators=(",", ":")) + "\n")
