"""``dpop-demo`` command-line entry point.

    dpop-demo serve   [--mode bearer|dpop] [--port N] [--ttl SECONDS]
    dpop-demo call     <tool> [--mode ...] [--arg k=v ...] [--json '{...}']
    dpop-demo list-tools [--mode ...]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from .config import load_settings


def _apply_env(args: argparse.Namespace) -> None:
    if getattr(args, "mode", None):
        os.environ["DPOP_MODE"] = args.mode
    if getattr(args, "port", None):
        os.environ["DPOP_PORT"] = str(args.port)
    if getattr(args, "ttl", None) is not None:
        os.environ["DPOP_ACCESS_TOKEN_TTL"] = str(args.ttl)


def _parse_args_kv(pairs: list[str], blob: str | None) -> dict:
    out: dict = {}
    if blob:
        out.update(json.loads(blob))
    for pair in pairs or []:
        key, _, raw = pair.partition("=")
        try:
            out[key] = json.loads(raw)
        except json.JSONDecodeError:
            out[key] = raw
    return out


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="dpop-demo", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_serve = sub.add_parser("serve", help="run the toy MCP payments server")
    p_serve.add_argument("--mode", choices=["bearer", "dpop"])
    p_serve.add_argument("--port", type=int)
    p_serve.add_argument("--ttl", type=int, help="access-token TTL in seconds (dpop mode)")

    p_call = sub.add_parser("call", help="call one tool")
    p_call.add_argument("tool")
    p_call.add_argument("--mode", choices=["bearer", "dpop"])
    p_call.add_argument("--port", type=int)
    p_call.add_argument("--arg", action="append", default=[], metavar="k=v")
    p_call.add_argument("--json", dest="blob", help="arguments as a JSON object")

    p_list = sub.add_parser("list-tools", help="list tool names")
    p_list.add_argument("--mode", choices=["bearer", "dpop"])
    p_list.add_argument("--port", type=int)

    args = parser.parse_args(argv)
    _apply_env(args)
    settings = load_settings()

    if args.command == "serve":
        from .server import serve

        print(f"serving ap2-toy-payments in {settings.mode!r} mode on {settings.base_url}", file=sys.stderr)
        serve(settings)
        return

    if args.command == "call":
        from .mcp_client import call_tool

        arguments = _parse_args_kv(args.arg, args.blob)
        result = _run(call_tool(settings, args.tool, arguments, mode=args.mode))
        print(json.dumps(result, indent=2))
        return

    if args.command == "list-tools":
        from .mcp_client import list_tools

        names = _run(list_tools(settings, mode=args.mode))
        print(json.dumps(names, indent=2))
        return


def _run(coro):
    """Run a client coroutine, turning expected failures into a one-line error."""
    from .mcp_client import AuthRejected, ServerUnreachable

    try:
        return asyncio.run(coro)
    except ServerUnreachable as exc:
        sys.exit(f"error: {exc}")
    except AuthRejected as exc:
        sys.exit(f"error: server rejected the request -- {exc}")


if __name__ == "__main__":  # pragma: no cover
    main()
