"""Shared helpers for the attacker scenarios.

Each scenario boots its own server subprocess on a free port with a
scenario-specific environment, runs a short async body, and prints a narrated
EXPECTED / GOT / verdict block. ``run_all.py`` collects the verdicts.
"""

from __future__ import annotations

import contextlib
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field

import httpx2

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class Server:
    mode: str
    env: dict[str, str] = field(default_factory=dict)
    port: int = field(default_factory=free_port)
    _proc: subprocess.Popen | None = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> "Server":
        environ = {
            **os.environ,
            "DPOP_MODE": self.mode,
            "DPOP_PORT": str(self.port),
            "DPOP_HOST": "127.0.0.1",
            "DPOP_BASE_URL": self.base_url,
            **self.env,
        }
        self._proc = subprocess.Popen(
            [sys.executable, "-m", "aaif_ap2_demo.cli", "serve", "--mode", self.mode],
            cwd=REPO_ROOT,
            env=environ,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                httpx2.get(f"{self.base_url}/", timeout=1)
                return self
            except Exception:
                time.sleep(0.15)
        self.__exit__(None, None, None)
        raise RuntimeError("server did not come up")

    def __exit__(self, *exc) -> None:
        if self._proc is not None:
            self._proc.terminate()
            with contextlib.suppress(Exception):
                self._proc.wait(timeout=5)
            self._proc = None


class Reporter:
    def __init__(self, title: str) -> None:
        self.title = title
        self.ok = True
        print(f"\n=== {title} ===")

    def step(self, msg: str) -> None:
        print(f"  - {msg}")

    def check(self, label: str, *, expected: str, got: str, passed: bool) -> None:
        mark = "PASS" if passed else "FAIL"
        self.ok = self.ok and passed
        print(f"  [{mark}] {label}\n         EXPECTED: {expected}\n         GOT:      {got}")

    def done(self) -> int:
        print(f"  => {'OK' if self.ok else 'FAILED'}: {self.title}")
        return 0 if self.ok else 1


def settings_for(port: int):
    """A Settings pointed at the scenario's server (env is per-process here)."""
    os.environ["DPOP_PORT"] = str(port)
    os.environ["DPOP_BASE_URL"] = f"http://127.0.0.1:{port}"
    from aaif_ap2_demo.config import load_settings

    return load_settings()
