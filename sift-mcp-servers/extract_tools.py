"""
extract_tools.py — introspect every sift_*.py server and emit Sift-MCP-Tools.md

Loads each server module in-process, asks FastMCP for its registered tool
catalog (tools/list-equivalent), and writes a markdown reference.

For the 7 codegen'd SIFT servers, every tool is the same generic
tool_<binary>(args: str) shape, so we collapse them into a per-server table
of binary names plus one template signature. The two hand-written servers
(sift-attack, sift-defend) get full per-tool sections because each tool has
a unique docstring + schema.
"""

import asyncio
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent
SERVERS = ROOT / "servers"
sys.path.insert(0, str(SERVERS))

# Servers in display order. First two are hand-written (forensic-decision
# tools); the rest are codegen'd SIFT-binary wrappers.
HAND_WRITTEN = ["sift_attack", "sift_defend"]
CODEGEN      = ["sift_disk", "sift_windows", "sift_network",
                "sift_memory", "sift_hashing", "sift_malware", "sift_crypto"]


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, SERVERS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def tools_of(mod):
    """Return [(name, description, inputSchema_dict), ...] sorted by name."""
    tools = asyncio.run(mod.mcp.list_tools())
    out = []
    for t in tools:
        schema = t.inputSchema if isinstance(t.inputSchema, dict) else {}
        out.append((t.name, t.description or "", schema))
    return sorted(out, key=lambda x: x[0])


def signature_line(name: str, schema: dict) -> str:
    """Render a Python-style call signature from the JSON schema."""
    props = schema.get("properties") or {}
    required = set(schema.get("required") or [])
    parts = []
    for pname, pdesc in props.items():
        ptype = pdesc.get("type", "any")
        if ptype == "array":
            item_type = (pdesc.get("items") or {}).get("type", "any")
            ptype = f"list[{item_type}]"
        if pname in required:
            parts.append(f"{pname}: {ptype}")
        else:
            default = pdesc.get("default", "")
            parts.append(f'{pname}: {ptype} = {default!r}')
    return f"{name}({', '.join(parts)})"


def md_for_hand_written(srv_id: str, tools: list) -> str:
    out = [f"## `{srv_id.replace('_', '-')}` — {len(tools)} tools\n"]
    for name, desc, schema in tools:
        sig = signature_line(name, schema)
        out.append(f"### `{name}`\n")
        out.append(f"```python\n{sig}\n```\n")
        cleaned = "\n".join(line.strip() for line in desc.strip().splitlines() if line.strip())
        if cleaned:
            out.append(cleaned + "\n")
        # parameters detail
        props = schema.get("properties") or {}
        if props:
            out.append("**Parameters:**")
            for pname, pdesc in props.items():
                ptype = pdesc.get("type", "any")
                required = pname in (schema.get("required") or [])
                star = "required" if required else f"optional (default={pdesc.get('default')!r})"
                out.append(f"- `{pname}` ({ptype}) — {star}")
            out.append("")
        out.append("")
    return "\n".join(out)


def md_for_codegen(srv_id: str, tools: list) -> str:
    display = srv_id.replace("_", "-")
    # The 7 codegen'd servers all use the same template — show it once.
    template_sig = "tool_<binary>(args: str = \"\") -> dict"
    out = [f"## `{display}` — {len(tools)} tools\n"]
    out.append(f"All tools share the same wrapper signature:\n")
    out.append(f"```python\n{template_sig}\n```\n")
    out.append("Pass arguments exactly as you would on the command line, "
               "e.g. `args=\"-r /evidence/image.e01\"`. "
               "Every call returns a structured dict with `stdout`, `stderr`, "
               "`exit_code`, `timestamp`, `duration_ms`, and is logged to the audit trail.\n")
    out.append("**Wrapped binaries (each exposed as `tool_<binary>`):**\n")
    # Render as a compact 4-column grid for readability
    names = [t[0].removeprefix("tool_") for t in tools]
    cols = 4
    rows = [names[i:i+cols] for i in range(0, len(names), cols)]
    out.append("| | | | |")
    out.append("|---|---|---|---|")
    for r in rows:
        padded = r + [""] * (cols - len(r))
        out.append("| " + " | ".join(f"`{x}`" if x else "" for x in padded) + " |")
    out.append("")
    return "\n".join(out)


def main():
    sections = []
    summary_rows = []
    print("loading servers...")

    for srv in HAND_WRITTEN + CODEGEN:
        print(f"  {srv}")
        mod = load(srv)
        tools = tools_of(mod)
        summary_rows.append((srv.replace("_", "-"), len(tools),
                             "hand-written" if srv in HAND_WRITTEN else "codegen"))
        if srv in HAND_WRITTEN:
            sections.append(md_for_hand_written(srv, tools))
        else:
            sections.append(md_for_codegen(srv, tools))

    total = sum(n for _, n, _ in summary_rows)
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    header = [
        "# SIFT-MCP Tool Reference",
        "",
        f"_Auto-generated by `extract_tools.py` on {when}. Do not edit by hand —",
        "re-run the extractor after any codegen run or hand-written server change._",
        "",
        f"**9 servers · {total} tools total**",
        "",
        "| Server | Tools | Source |",
        "|---|---:|---|",
    ]
    for name, n, kind in summary_rows:
        header.append(f"| `{name}` | {n} | {kind} |")

    header += [
        "",
        "## Response envelope (every tool)",
        "",
        "Every tool returns a Python `dict`. The hand-written servers wrap their result in:",
        "",
        "```json",
        "{",
        '  "tool":          "<tool name>",',
        '  "server":        "sift-attack | sift-defend",',
        '  "timestamp":     "<ISO 8601 UTC>",',
        '  "data":          { ...tool-specific... },',
        '  "forensic_note": "<one-line analyst hint>"',
        "}",
        "```",
        "",
        "The 7 codegen'd SIFT servers wrap subprocess output in:",
        "",
        "```json",
        "{",
        '  "tool":        "<binary name>",',
        '  "server":      "sift-<category>",',
        '  "command":     "<full argv joined>",',
        '  "exit_code":   <int>,',
        '  "stdout":      "<truncated to 50k chars>",',
        '  "stderr":      "<stripped, or null>",',
        '  "timestamp":   "<ISO 8601 UTC>",',
        '  "duration_ms": <int>,',
        '  "installed":   <bool>',
        "}",
        "```",
        "",
        "Every call is appended as a single JSON line to `logs/<server-name>.jsonl`.",
        "",
        "## How to test the whole thing",
        "",
        "Inside WSL Ubuntu-22.04, from the project root with the venv active:",
        "",
        "```bash",
        ". .venv/bin/activate",
        "python verify.py                  # 7 SIFT servers: load + 1 probe each",
        "python verify_attack_defend.py    # sift-attack + sift-defend: 12 functional checks",
        "python audit_tools.py             # every SIFT binary: 5s probe per binary",
        "python phase5_report.py           # speed + coverage report",
        "",
        "# real MCP stdio handshake against any server:",
        "printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"x\",\"version\":\"0\"}}}\\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\\n' \\",
        "  | uvx --from servers sift-attack",
        "",
        "# interactive Inspector against any server:",
        "npx -y @modelcontextprotocol/inspector wsl.exe -d Ubuntu-22.04 -- \\",
        "  /home/$USER/.local/bin/uvx --from /mnt/c/path/to/servers sift-attack",
        "```",
        "",
        "---",
        "",
    ]

    md = "\n".join(header) + "\n".join(sections)
    out_path = ROOT / "Sift-MCP-Tools.md"
    out_path.write_text(md, encoding="utf-8")
    print(f"\nwrote {out_path}  ({len(md):,} chars, {total} tools across {len(summary_rows)} servers)")


if __name__ == "__main__":
    main()
