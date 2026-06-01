"""
audit_tools.py — probe every tool in registry.json

For each registered binary, try common no-side-effect flags in order:
    --version, -V, --help, -h
First one that returns within 5s with any output gets it marked OK.

Outcomes:
    OK         binary responded to at least one probe flag
    HANG       all probes timed out (binary likely TUI / waits on stdin)
    MISSING    full_path no longer exists on disk
    ERR_ALL    every probe returned non-zero AND empty stdout/stderr
"""

import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

REGISTRY = Path(__file__).parent / "registry.json"
PROBES   = ["--version", "-V", "--help", "-h"]
TIMEOUT  = 5  # seconds per probe


def probe(full_path: str) -> tuple[str, str]:
    """Returns (status, evidence_flag_or_reason)."""
    if not Path(full_path).is_file():
        return ("MISSING", "")

    all_timed_out = True
    saw_any_output = False

    for flag in PROBES:
        try:
            r = subprocess.run(
                [full_path, flag],
                capture_output=True, text=True,
                timeout=TIMEOUT,
            )
            all_timed_out = False
            out = (r.stdout or "") + (r.stderr or "")
            if out.strip():
                saw_any_output = True
                if r.returncode == 0 or len(out.strip()) > 4:
                    return ("OK", flag)
        except subprocess.TimeoutExpired:
            continue
        except Exception as e:
            return ("ERR_ALL", f"{type(e).__name__}: {e}")

    if all_timed_out:
        return ("HANG", "all probes timed out")
    if saw_any_output:
        return ("OK", "saw output but nonzero exits")
    return ("ERR_ALL", "all probes returned no output")


def main() -> int:
    reg = json.loads(REGISTRY.read_text())
    servers = reg["servers"]

    overall = defaultdict(int)
    per_server: dict[str, dict[str, int]] = {}
    issues: list[tuple[str, str, str, str]] = []  # (server, binary, status, why)

    total = sum(len(v) for v in servers.values())
    print(f"probing {total} tools, {TIMEOUT}s timeout per probe flag\n")

    for server, tools in sorted(servers.items()):
        counts = defaultdict(int)
        for i, t in enumerate(tools, 1):
            status, why = probe(t["full_path"])
            counts[status] += 1
            overall[status] += 1
            if status != "OK":
                issues.append((server, t["binary"], status, why))
            mark = {"OK": "✓", "HANG": "⏳", "MISSING": "?", "ERR_ALL": "✗"}[status]
            sys.stdout.write(f"\r  sift-{server:<10} [{i:>3}/{len(tools):<3}] {mark} {t['binary']:<30}")
            sys.stdout.flush()
        sys.stdout.write("\n")
        per_server[server] = dict(counts)

    print("\n" + "═" * 60)
    print("  PER-SERVER RESULTS")
    print("═" * 60)
    print(f"  {'server':<16} {'OK':>5} {'HANG':>5} {'MISS':>5} {'ERR':>5} {'TOTAL':>6}")
    for server in sorted(per_server):
        c = per_server[server]
        print(f"  sift-{server:<11} "
              f"{c.get('OK',0):>5} "
              f"{c.get('HANG',0):>5} "
              f"{c.get('MISSING',0):>5} "
              f"{c.get('ERR_ALL',0):>5} "
              f"{sum(c.values()):>6}")

    print("\n" + "═" * 60)
    print("  OVERALL")
    print("═" * 60)
    for k in ("OK", "HANG", "MISSING", "ERR_ALL"):
        pct = 100.0 * overall[k] / total if total else 0
        print(f"  {k:<10} {overall[k]:>4} ({pct:5.1f}%)")
    print(f"  TOTAL      {total:>4}")

    if issues:
        # write a CSV-ish detail file for follow-up
        detail = Path(__file__).parent / "audit_issues.txt"
        with detail.open("w") as f:
            f.write("server\tbinary\tstatus\twhy\n")
            for row in issues:
                f.write("\t".join(row) + "\n")
        print(f"\n  Issue detail → {detail.name} ({len(issues)} tools)")

    return 0 if overall["OK"] == total else 1


if __name__ == "__main__":
    sys.exit(main())
