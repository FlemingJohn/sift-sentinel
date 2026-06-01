"""
verify.py — end-to-end smoke test for every generated SIFT MCP server.

For each sift_<server>.py in servers/:
  1. Import the module (catches syntax errors, missing imports).
  2. Enumerate registered FastMCP tools.
  3. Pick a probe binary, call it with --version / -V / --help.
  4. Confirm exit_code == 0 (or at least a non-error dispatch).
  5. Confirm an audit log line was written.

Exits non-zero if any server fails any check.
"""

import asyncio
import importlib.util
import json
import sys
from pathlib import Path

SERVERS_DIR = Path(__file__).parent / "servers"

# One probe per server — small, fast, side-effect-free.
# (tool_fn_name, args_to_pass)
PROBES = {
    "sift-disk":     ("tool_fls",            "-V"),
    "sift-windows":  ("tool_regfinfo",       "-h"),
    "sift-network":  ("tool_ngrep",          "-V"),       # tshark not installed in this WSL
    "sift-memory":   ("tool_bulk_extractor", "-V"),
    "sift-hashing":  ("tool_md5deep",        "-v"),
    "sift-malware":  ("tool_radare2",        "-v"),
    "sift-crypto":   ("tool_ccrypt",         "--version"),  # cryptsetup bin is in cryptsetup-bin pkg
}


def load(server_file: Path):
    spec = importlib.util.spec_from_file_location(server_file.stem, server_file)
    mod  = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(server_file.parent))
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    sys.path.insert(0, str(SERVERS_DIR))

    # Filter to actual FastMCP servers — exclude data/helper modules like sift_attack_map.py
    server_files = [
        sf for sf in sorted(SERVERS_DIR.glob("sift_*.py"))
        if "FastMCP(" in sf.read_text(encoding="utf-8", errors="ignore")
    ]
    if not server_files:
        print(f"FAIL: no sift_*.py under {SERVERS_DIR}")
        return 1

    failures = 0
    print(f"verifying {len(server_files)} server files in {SERVERS_DIR}\n")

    for sf in server_files:
        server_name = "sift-" + sf.stem.split("_", 1)[1]
        print(f"── {server_name} ─── ({sf.name})")

        try:
            mod = load(sf)
        except Exception as e:
            print(f"   IMPORT FAIL: {type(e).__name__}: {e}")
            failures += 1
            continue

        try:
            tools = asyncio.run(mod.mcp.list_tools())
        except Exception as e:
            print(f"   list_tools FAIL: {e}")
            failures += 1
            continue
        print(f"   tools registered : {len(tools)}")

        probe = PROBES.get(server_name)
        if not probe:
            print(f"   no probe defined for {server_name} — skipping dispatch")
            continue

        fn_name, args = probe
        fn = getattr(mod, fn_name, None)
        if fn is None:
            print(f"   probe FAIL: {fn_name} not in module")
            failures += 1
            continue

        try:
            r = fn(args)
        except Exception as e:
            print(f"   dispatch FAIL ({fn_name} {args}): {e}")
            failures += 1
            continue

        installed  = r.get("installed")
        exit_code  = r.get("exit_code")
        err        = r.get("error")
        stdout_head = (r.get("stdout") or "").splitlines()[0][:60] if r.get("stdout") else ""

        if err:
            print(f"   dispatch       : {fn_name} {args}  →  error: {err}")
            if not installed:
                print(f"                    (binary not installed — non-fatal for verify)")
            else:
                failures += 1
            continue

        ok = (exit_code == 0) or (stdout_head != "")
        status = "OK" if ok else "FAIL"
        print(f"   dispatch       : {fn_name} {args}  →  exit={exit_code}  {status}")
        print(f"   stdout[0]      : {stdout_head!r}")
        if not ok:
            failures += 1

        # AuditLogger writes to ./logs/ relative to cwd, not relative to the server file.
        log = Path.cwd() / "logs" / f"{server_name}.jsonl"
        if log.exists():
            last = log.read_text().strip().splitlines()[-1]
            entry = json.loads(last)
            print(f"   audit tail     : tool={entry.get('tool')} exit={entry.get('exit_code')} dur={entry.get('duration_ms')}ms")
        else:
            print(f"   audit log MISSING: {log}")
            failures += 1

        print()

    print("═" * 56)
    if failures == 0:
        print(f"  ALL {len(server_files)} SERVERS VERIFIED")
        return 0
    print(f"  {failures} FAILURE(S) across {len(server_files)} servers")
    return 1


if __name__ == "__main__":
    sys.exit(main())
