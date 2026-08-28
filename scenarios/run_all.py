"""Run every scenario in order and print a summary table.

    uv run python scenarios/run_all.py
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

SCENARIOS = [
    "01_static_bearer_replay",
    "02_dpop_happy_path",
    "03_dpop_stolen_token",
    "04_dpop_replayed_proof",
    "05_dpop_token_expiry",
]


def main() -> int:
    results: list[tuple[str, int]] = []
    for name in SCENARIOS:
        mod = importlib.import_module(name)
        rc = mod.main()
        results.append((name, rc))

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for name, rc in results:
        print(f"  {'OK  ' if rc == 0 else 'FAIL'}  {name}")
    failed = [n for n, rc in results if rc != 0]
    print("=" * 60)
    print("all scenarios passed" if not failed else f"FAILED: {', '.join(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
