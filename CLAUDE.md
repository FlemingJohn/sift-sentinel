# CLAUDE.md — SIFT‑Sentinel agent & operator guide

Canonical setup / install / run guide for this repo. Any AI agent or human
operator should be able to read this file top‑to‑bottom and run an
investigation. `AGENTS.md` is a short quickstart that points back here.

---

## 1. What this is

SIFT‑Sentinel is an AI‑driven DFIR (digital forensics & incident response)
platform. A supervisor/specialist pipeline built on the **Claude Agent SDK**
drives **400+ forensic tools** exposed over **MCP**, then maps findings to
**MITRE ATT&CK** and **D3FEND** and writes a report.

> The README badges still say "LangGraph". That is stale. The live pipeline is
> the **Agent SDK** code under `sift-agent/agent_sdk/`. Treat this file, not the
> top‑level README, as the source of truth for how to run.

---

## 2. Critical execution model (read this before anything else)

```
 Windows host (Windows Terminal)              WSL: Ubuntu-22.04
 ────────────────────────────────            ────────────────────────────
  python main.py / tui.py                      python3 sift_disk.py   (MCP)
  Claude Agent SDK   ──── wsl.exe -d ... ───▶  python3 sift_memory.py (MCP)
  hashing (host, hashlib)                      python3 sift_*.py      (MCP)
                                               + SIFT forensic binaries
```

- **The agent process runs on the Windows host, NOT inside WSL.** It launches
  each MCP server into WSL with `wsl.exe -d Ubuntu-22.04 -- python3 <server>.py`
  (see `sift-agent/agent_sdk/mcp_servers.py`).
- The **host** Python must have `claude-agent-sdk` (and `textual` for the TUI).
- **WSL** must have `python3` plus the SIFT forensic binaries on PATH, and must
  be able to read the evidence files.
- **Hashing** runs on the host: it converts a `/mnt/c/...` path back to
  `C:\...` automatically (`deterministic_hashing.py`).
- **Analysis tools** run in WSL. The controller first creates space‑free
  symlinks at `/var/tmp/sift-evidence/<name>` so the space in
  `"SIFT - Sentinel"` never breaks a tool invocation.

**Consequence:** always pass evidence as a **WSL path** (`/mnt/c/...`), never a
Windows path. The host side translates when it needs to.

---

## 3. Prerequisites

| Where | Needs |
|-------|-------|
| Windows host | Python 3.10+, this repo, network access for the SDK |
| WSL (`Ubuntu-22.04`) | Python 3.10+, the SIFT forensic toolchain, `p7zip-full`, read access to `/mnt/c/.../sift-datasets` |
| Auth | A Claude subscription login **or** `ANTHROPIC_API_KEY` |

Check WSL is present and named as expected:

```powershell
wsl.exe -l -v          # confirm a distro named Ubuntu-22.04 exists and is v2
```

If your distro has a different name, set `SIFT_WSL_DISTRIBUTION` (see §6).

---

## 4. Install

Run on the **Windows host** (PowerShell or Windows Terminal):

```powershell
# from repo root: C:\Users\FlemingJohn\Downloads\SIFT - Sentinel
python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install -r sift-agent\requirements.txt   # claude-agent-sdk
pip install -r sift-tui\requirements.txt      # textual + python-dotenv (TUI only)
```

Inside **WSL**, make sure the MCP servers import and the forensic tools exist:

```bash
wsl -d Ubuntu-22.04
sudo apt-get install -y p7zip-full python3            # if missing
python3 "/mnt/c/Users/FlemingJohn/Downloads/SIFT - Sentinel/sift-mcp-servers/servers/sift_disk.py" --help 2>/dev/null; echo done
```

Configure the environment file:

```powershell
copy sift-agent\.env.example sift-agent\.env
```

Then edit `sift-agent\.env` — see §6 for every variable.

---

## 5. The datasets

Located at `sift-datasets/` on the Windows side, which WSL sees under `/mnt/c/...`:

| File | Type | Note |
|------|------|------|
| `base-dc-cdrive.E01` | Disk image (EnCase) | ~12 GB. Use directly. |
| `base-dc-memory.7z` | Memory dump (compressed) | **Extract first** (§5.1). |
| `base-file-memory.7z` | Memory dump (compressed) | **Extract first** (§5.1). |

### 5.1 Extract the memory dumps in WSL

```bash
cd "/mnt/c/Users/FlemingJohn/Downloads/SIFT - Sentinel/sift-datasets"
7z x base-dc-memory.7z
7z x base-file-memory.7z
```

> ⚠️ **Extension matters for classification.** The controller treats `.raw` as a
> **disk** image, not memory (`investigation_controller.py`:
> `DISK_EXTENSIONS` vs `MEMORY_EXTENSIONS`). Memory is recognised by
> `.mem .vmem .dmp .lime .raw_mem`. If 7z yields a `.raw`, rename it so it is
> classified as memory:
> ```bash
> mv base-dc-memory.raw base-dc-memory.mem
> ```

### 5.2 Evidence path form to pass on the CLI

Always WSL form, e.g.:

```
/mnt/c/Users/FlemingJohn/Downloads/SIFT - Sentinel/sift-datasets/base-dc-cdrive.E01
```

The path contains a space — that's fine, the controller symlinks it to a
space‑free name before tools run. Quote it in the shell.

---

## 6. Configuration (`sift-agent/.env`)

| Variable | Default | Meaning |
|----------|---------|---------|
| `ANTHROPIC_API_KEY` | unset | Leave unset to run keyless on a Claude login; set to bill the API. |
| `SIFT_WSL_DISTRIBUTION` | `Ubuntu-22.04` | WSL distro hosting MCP servers + binaries. Match `wsl -l -v`. |
| `SIFT_MCP_SERVERS_DIRECTORY` | `/mnt/c/.../sift-mcp-servers/servers` | MCP scripts as seen **from inside WSL**. |
| `SIFT_WORKER_MODEL` | `haiku` | Specialist model tier. |
| `SIFT_SUPERVISOR_MODEL` | `opus` | Supervisor / synthesis model tier. |
| `SIFT_REPORTS_DIRECTORY` | `./reports` | Where reports are written. |
| `SIFT_AUDIT_LOG_DIRECTORY` | `./logs` | Where audit `.jsonl` lands. |
| `SIFT_MAXIMUM_TURNS_PER_SPECIALIST` | `40` | Per‑specialist turn cap. |
| `SIFT_MAXIMUM_ANALYSIS_ATTEMPTS` | `2` | Retries when a specialist returns zero findings. |
| `SIFT_MAXIMUM_BUDGET_USD` | `5.0` | Hard spend guardrail per run. |

If you edit `SIFT_MCP_SERVERS_DIRECTORY`, keep it a **WSL** path.

---

## 7. Run

### 7.1 CLI (headless)

```powershell
# from repo root, venv active
cd sift-agent\agent_sdk
python main.py --case-id base-dc-01 --evidence "/mnt/c/Users/FlemingJohn/Downloads/SIFT - Sentinel/sift-datasets/base-dc-cdrive.E01"
```

Multiple evidence files (disk + memory together):

```powershell
python main.py --case-id base-dc-01 `
  --evidence "/mnt/c/Users/FlemingJohn/Downloads/SIFT - Sentinel/sift-datasets/base-dc-cdrive.E01" `
              "/mnt/c/Users/FlemingJohn/Downloads/SIFT - Sentinel/sift-datasets/base-dc-memory.mem"
```

`--case-id` and `--evidence` are required; `--evidence` takes one or more paths.

### 7.2 TUI (the "WSL UI" / live dashboard)

The dashboard is the Textual TUI. **Run it from the Windows host (Windows
Terminal), not inside WSL** — it imports `sift-agent/agent_sdk` and launches the
MCP servers into WSL itself.

```powershell
# from repo root, venv active
cd sift-tui
python tui.py --case-id base-dc-01 --evidence "/mnt/c/Users/FlemingJohn/Downloads/SIFT - Sentinel/sift-datasets/base-dc-cdrive.E01"
```

Keys: `q` quit · `e` export state snapshot · `c` clear tool log.

Panels: phase bar (acquire → hash → analyze → attribute → report → done),
AGENTS, FINDINGS (with ATT&CK), EVIDENCE & INTEGRITY, TOOL STREAM, and a
token/cost status line.

If `sift-agent/agent_sdk` is not the sibling folder:
```powershell
$env:SIFT_AGENT_DIR = "C:\path\to\sift-agent\agent_sdk"
```

### 7.3 Investigation phases

`acquire → hash (gate) → analyze → attribute (ATT&CK + D3FEND, gate) → report`.
Gates can **halt** the run (`hash_ok`, `attribution_ok`); a halt reason is logged
and printed in the summary. Output: a report under `SIFT_REPORTS_DIRECTORY` and
an audit `.jsonl` under `SIFT_AUDIT_LOG_DIRECTORY`.

---

## 8. Verify the environment (no evidence needed)

From `sift-mcp-servers/`:

```powershell
python verify.py                  # all 9 MCP servers load
python verify_attack_defend.py    # ATT&CK / D3FEND corpora resolve
python audit_tools.py             # forensic binaries present
```

From `sift-agent/agent_sdk/`:

```powershell
python test_pure_logic.py         # controller logic, no SDK/WSL calls
```

---

## 9. Handling evidence safely in WSL

These images come from a simulated breach (a domain controller and a file
server) and may contain **live malware and real credentials/PII**. Treat them as
hostile data, not trusted files.

1. **Read‑only by default.** Never mount a disk image read‑write. If you mount
   the E01 manually, force read‑only and noexec:
   ```bash
   mkdir -p /mnt/case && \
   ewfmount base-dc-cdrive.E01 /mnt/ewf && \
   mount -o ro,noexec,nodev,nosuid,loop /mnt/ewf/ewf1 /mnt/case
   ```
   The pipeline itself only reads; it does not mount read‑write.
2. **Verify before you trust.** The hash phase records MD5/SHA‑1/SHA‑256 into the
   chain of custody. Keep a known‑good hash list and compare. Work on copies if
   you need to experiment; keep one pristine master.
3. **Never execute extracted artifacts.** Do not run binaries carved from the
   disk or strings pulled from memory on your host or in this WSL. Detonate only
   in a disposable, network‑isolated VM.
4. **Contain the blast radius.** WSL2 shares the host kernel and `/mnt/c` is your
   real C: drive — it is *not* a sandbox. For untrusted detonation use a separate
   throwaway distro (`wsl --import` a scratch instance) or a real VM, and cut its
   network (`wsl --shutdown` between runs; consider `networkingMode=none` in
   `.wslconfig`).
5. **Lock down permissions & keep evidence out of git.** Restrict the dataset
   dir (`chmod -R a-w sift-datasets` to make it read‑only). The 12 GB E01 and the
   memory dumps must **not** be committed — see §11.
6. **Don't leak evidence to third parties.** Findings/snapshots may contain PII
   and secrets. Keep `reports/` and `logs/` local; scrub before sharing. If you
   later wire in `sift-guard` (T3 TEE chain‑of‑custody, see
   `sift-datasets/README.md`), that seals custody but still transmits summaries —
   review what leaves the host.

---

## 10. Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| `wsl.exe ... not found` / server won't start | Wrong `SIFT_WSL_DISTRIBUTION`. Check `wsl -l -v`. |
| Tool can't find evidence | Passed a Windows path. Use `/mnt/c/...`. Confirm WSL can `ls` it. |
| Memory dump analysed as a disk | Extracted file ends in `.raw`. Rename to `.mem`/`.lime` (§5.1). |
| `no_evidence` halt | `--evidence` path doesn't resolve inside WSL. |
| Auth errors | Set `ANTHROPIC_API_KEY`, or log in to a Claude subscription. |
| Run stops early with a halt reason | A gate failed (`hash_ok`/`attribution_ok`); read the audit log. |
| Hashing fails on host | The `/mnt/<drive>/...` path must map to a real Windows drive. |

---

## 11. Repo hygiene

The datasets are **not** currently in `.gitignore`. Do not commit them
(`base-dc-cdrive.E01` alone is ~12 GB). Add to `.gitignore`:

```
sift-datasets/*.E01
sift-datasets/*.7z
sift-datasets/*.mem
sift-datasets/*.raw
sift-datasets/*.dmp
sift-datasets/*.lime
```

(`logs/`, `*.log`, `reports/`, `.env`, and `.venv/` are already ignored.)

---

## 12. Map of the repo

```
SIFT - Sentinel/
├── CLAUDE.md                  ← you are here (canonical)
├── AGENTS.md                  ← quickstart pointer to this file
├── sift-agent/
│   ├── .env / .env.example    ← all SIFT_* config
│   └── agent_sdk/             ← LIVE pipeline (Agent SDK)
│       ├── main.py            ← CLI entry point
│       ├── investigation_controller.py  ← phase orchestration
│       ├── mcp_servers.py     ← launches MCP servers into WSL
│       ├── specialists.py / specialist_runner.py / routing.py
│       ├── configuration.py   ← reads SIFT_* env vars
│       └── deterministic_hashing.py / case_state.py / report_synthesizer.py
├── sift-mcp-servers/servers/  ← 9 MCP servers (sift_*.py), run inside WSL
├── sift-tui/tui.py            ← live dashboard (run on host)
├── sift-datasets/             ← evidence (E01 + memory 7z) — keep out of git
└── sift-documents/            ← deeper architecture docs
```
