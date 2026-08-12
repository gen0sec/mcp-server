#!/usr/bin/env python3
"""End-to-end launch smoke test: does the packed server actually start?

Launches ``server/run.py`` exactly the way the manifest does (the given Python
interpreter, ``PYTHONPATH`` pointed at ``server/lib``) and drives a real MCP
stdio ``initialize`` handshake. Passing proves the dependency-resolution path
— bundled fast-path OR the first-run venv fallback — produces a working server.

This is the regression guard for the 0.0.7 crash, where a bundle vendored under
one Python ABI was launched under another: run it here with ``--python`` set to
a DIFFERENT interpreter than the one that populated ``server/lib`` and it must
still pass (the venv fallback rescues the mismatch).

Uses only the standard library so it can run under any bare interpreter.
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RUN_PY = REPO_ROOT / "server" / "run.py"
SERVER_LIB = REPO_ROOT / "server" / "lib"
EXPECTED_SERVER_NAME = "WAF rule generation"


def _reader(stream, q: "queue.Queue[str | None]") -> None:
    for line in iter(stream.readline, ""):
        q.put(line)
    q.put(None)  # EOF sentinel


def _drain(stream, sink: list) -> None:
    for line in iter(stream.readline, ""):
        sink.append(line)


def run_smoke(python: str, lib: str | None, timeout: float) -> int:
    env = dict(os.environ)
    # Mirror the manifest: PYTHONPATH pinned at server/lib.
    if lib:
        env["PYTHONPATH"] = lib
    else:
        env.pop("PYTHONPATH", None)
    # A clean bootstrap every run, so a stale flag can't mask a real failure.
    env.pop("GEN0SEC_MCP_BOOTSTRAPPED", None)

    proc = subprocess.Popen(
        [python, str(RUN_PY)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env=env,
    )

    out_q: "queue.Queue[str | None]" = queue.Queue()
    err_lines: list = []
    threading.Thread(target=_reader, args=(proc.stdout, out_q), daemon=True).start()
    threading.Thread(target=_drain, args=(proc.stderr, err_lines), daemon=True).start()

    def fail(msg: str) -> int:
        proc.kill()
        sys.stderr.write(f"[smoke] FAIL: {msg}\n")
        if err_lines:
            sys.stderr.write("[smoke] --- server stderr ---\n")
            sys.stderr.write("".join(err_lines[-40:]))
        return 1

    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "gen0sec-smoke", "version": "0"},
        },
    }
    try:
        proc.stdin.write(json.dumps(request) + "\n")
        proc.stdin.flush()
    except (BrokenPipeError, OSError):
        return fail("server exited before it could read initialize")

    # Read newline-delimited JSON-RPC until we see the response to id=1.
    # Non-JSON lines (stray logging on stdout) are skipped defensively.
    while True:
        try:
            line = out_q.get(timeout=timeout)
        except queue.Empty:
            return fail(f"no initialize response within {timeout:.0f}s")
        if line is None:
            return fail(f"server closed stdout (exit={proc.poll()}) before responding")
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("id") != 1:
            continue
        if "error" in msg:
            return fail(f"initialize returned error: {msg['error']}")
        result = msg.get("result") or {}
        name = (result.get("serverInfo") or {}).get("name")
        if name != EXPECTED_SERVER_NAME:
            return fail(f"unexpected serverInfo.name: {name!r} (result={result})")
        break

    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    print(f"[smoke] OK: '{EXPECTED_SERVER_NAME}' initialized under {python} "
          f"(PYTHONPATH={'<server/lib>' if lib else '<unset>'})")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--python", default=sys.executable,
                    help="Interpreter used to launch run.py (default: this one).")
    ap.add_argument("--lib", default=str(SERVER_LIB),
                    help="PYTHONPATH value, mirroring the manifest (default: server/lib). "
                         "Pass '' to leave PYTHONPATH unset.")
    ap.add_argument("--timeout", type=float, default=420.0,
                    help="Seconds to wait for initialize (allows a one-time venv build).")
    args = ap.parse_args()
    return run_smoke(args.python, args.lib or None, args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
