# AGENTS.md — SIFT‑Sentinel

Quickstart for any AI agent or operator. **Full guide: [`CLAUDE.md`](./CLAUDE.md)**
(setup, config, dataset prep, security, troubleshooting). Read it before a real run.

## The one thing to remember

The agent runs on the **Windows host**; it launches the MCP forensic servers
**into WSL** via `wsl.exe -d Ubuntu-22.04`. So:

- Run `main.py` / `tui.py` from the **Windows host** (Windows Terminal), not WSL.
- Pass evidence as **WSL paths** (`/mnt/c/...`), never Windows paths.
- The live pipeline is `sift-agent/agent_sdk/` (the README's "LangGraph" is stale).

## Install (Windows host, repo root)

```powershell
python -m venv .venv ; .\.venv\Scripts\Activate.ps1
pip install -r sift-agent\requirements.txt    # claude-agent-sdk
pip install -r sift-tui\requirements.txt       # textual (TUI only)
copy sift-agent\.env.example sift-agent\.env   # then edit; set SIFT_WSL_DISTRIBUTION
```

In WSL, ensure `python3` + `p7zip-full` + the SIFT forensic binaries exist and
can read `/mnt/c/.../sift-datasets`.

## Prepare datasets (in WSL)

```bash
cd "/mnt/c/Users/FlemingJohn/Downloads/SIFT - Sentinel/sift-datasets"
7z x base-dc-memory.7z ; 7z x base-file-memory.7z
# If extraction yields a .raw, rename so it's classified as MEMORY not DISK:
# mv base-dc-memory.raw base-dc-memory.mem
```

(`base-dc-cdrive.E01` is used as‑is.)

## Run — CLI

```powershell
cd sift-agent\agent_sdk
python main.py --case-id base-dc-01 --evidence "/mnt/c/Users/FlemingJohn/Downloads/SIFT - Sentinel/sift-datasets/base-dc-cdrive.E01"
```

## Run — TUI (the live dashboard / "UI")

```powershell
cd sift-tui
python tui.py --case-id base-dc-01 --evidence "/mnt/c/Users/FlemingJohn/Downloads/SIFT - Sentinel/sift-datasets/base-dc-cdrive.E01"
```

Keys: `q` quit · `e` export snapshot · `c` clear tool log.

## Verify environment (no evidence needed)

```powershell
cd sift-mcp-servers ; python verify.py ; python verify_attack_defend.py ; python audit_tools.py
```

## Phases & output

`acquire → hash (gate) → analyze → attribute (ATT&CK + D3FEND, gate) → report`.
Report → `SIFT_REPORTS_DIRECTORY` (default `./reports`); audit JSONL →
`SIFT_AUDIT_LOG_DIRECTORY` (default `./logs`).

## Handle evidence as hostile

These are breach images with possible live malware/PII. Read‑only; never execute
carved artifacts on the host; detonate only in an isolated throwaway VM. WSL2 is
**not** a sandbox (`/mnt/c` is your real C:). Keep `sift-datasets/`, `reports/`,
`logs/` out of git. Details in `CLAUDE.md` §9 & §11.
