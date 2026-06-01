# sift-tui

A live **DFIR investigation dashboard** (Textual TUI) for the `sift-agent`
LangGraph pipeline. It runs the same graph as `sift-agent/run.py` but renders
progress as panels instead of scrolling console lines.

```
┌─ SIFT-Agent · case rocba-01 ───────────────── ANALYZING ──┐
│ acquire ▸ hash ▸ [analyze] ▸ attribute ▸ defend ▸ done     │
├───────────────────────┬───────────────────────────────────┤
│ AGENTS                │ FINDINGS                           │
│ ✓ acquirer  ..  tok   │ id   claim          conf   ATT&CK  │
│ ⟳ filesystem ..       │ f3a1 reg Run-key…  ● conf T1547.001│
│ ⟳ windows   ..        ├───────────────────────────────────┤
│                       │ EVIDENCE & INTEGRITY               │
│ TOOL STREAM           │ rocba-cdrive.e01  sha256 ✓  CoC ✓  │
│ [Tool] windows evtx…  │ rocba-memory.raw  sha256 ✓  CoC ✓  │
├───────────────────────┴───────────────────────────────────┤
│ tokens in 84k / out 12k  tools 41  errors 0  est $0.41     │
└─────────────────────────────────────────────────────────────┘
```

## How it connects to sift-agent

`tui.py` adds the sibling `../sift-agent` folder to `sys.path` and imports its
`build_graph`, `state`, and `console_logger` modules. The logger was refactored
into a **pluggable sink** dispatcher, so the CLI (`run.py`) and this TUI share
**one** event stream — the TUI just registers a `TuiSink` and silences the
console renderer while it owns the screen.

Two event feeds drive the panels:
- `graph.astream(stream_mode="values")` -> FINDINGS + EVIDENCE (full snapshots)
- `console_logger` events -> AGENTS panel + TOOL STREAM (live activity)

## Install

```bash
pip install -r ../sift-agent/requirements.txt   # the agent + langgraph deps
pip install -r requirements.txt                 # textual
```

If `sift-agent` is not the sibling folder, point to it:
```bash
export SIFT_AGENT_DIR=/path/to/sift-agent
```

## Run (inside WSL/Linux, so the MCP servers reach the SIFT binaries)

```bash
python tui.py --case-id rocba-01 --evidence /mnt/c/evidence/rocba-cdrive.e01
# multiple files:
python tui.py --case-id net-01 --evidence /mnt/c/ev/dc.E01 /mnt/c/ev/dc-mem.raw
```

Keys: `q` quit · `e` export state snapshot · `c` clear tool log.

## Backends

`--backend memory` (default, simplest for a live demo) or `--backend sqlite`
(persists checkpoints to `SIFT_SQLITE_PATH`).
