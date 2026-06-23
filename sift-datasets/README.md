# sift-guard

A T3 ADK MCP server that wraps SIFT-Sentinel's investigation output with hardware-guaranteed chain of custody. SIFT does the forensics. sift-guard makes the evidence legally defensible.

```
SIFT-Sentinel (Python)
  └── calls sift-guard over MCP stdio
        └── sift-guard (TypeScript) calls T3 ADK
              └── T3 Network seals data in TEE hardware
                    └── issues court-admissible certificate
```

---

## What it adds to SIFT

| SIFT today | With sift-guard |
|---|---|
| Audit log saved to local `.jsonl` file | Audit log sealed inside T3 hardware enclave |
| No investigator identity on record | Every phase stamped with investigator DID |
| Software hash gate only | Hardware-verified evidence integrity |
| No external proof of authenticity | Court-admissible verifiable certificate |

---

## Prerequisites

- Node.js 18+
- A T3 Network account → [terminal3.io](https://terminal3.io)
- An Ethereum wallet private key (used as investigator identity)
- SIFT-Sentinel already set up and running

---

## Installation

Clone or copy the `sift-guard` folder into your SIFT-Sentinel project root:

```
SIFT - Sentinel/
├── sift-agent/
├── sift-mcp-servers/
├── sift-tui/
└── sift-guard/          ← place it here
```

Install dependencies inside `sift-guard`:

```bash
cd sift-guard
npm install
npm run build
```

Set up environment variables:

```bash
cp .env.example .env
```

Open `.env` and fill in your values:

```
T3_INVESTIGATOR_PRIVATE_KEY=0xyour_ethereum_private_key_here
T3_NETWORK_ENDPOINT=https://sandbox.terminal3.io
```

> Get your T3 sandbox credentials at [terminal3.io](https://terminal3.io). The sandbox gives you 20,000 free test tokens.

---

## Integration into SIFT-Sentinel

### Step 1 — Register sift-guard as an MCP server

Open `sift-agent/agent_sdk/mcp_servers.py` and add the `sift-guard` entry to your existing server dictionary:

```python
import os

MCP_SERVERS = {
    "sift-disk":    { "command": "wsl", "args": [...] },
    "sift-memory":  { "command": "wsl", "args": [...] },
    "sift-network": { "command": "wsl", "args": [...] },
    "sift-malware": { "command": "wsl", "args": [...] },
    "sift-windows": { "command": "wsl", "args": [...] },
    "sift-crypto":  { "command": "wsl", "args": [...] },
    "sift-hashing": { "command": "wsl", "args": [...] },
    "sift-attack":  { "command": "wsl", "args": [...] },
    "sift-defend":  { "command": "wsl", "args": [...] },

    "sift-guard": {
        "command": "node",
        "args": [
            os.path.join(
                os.path.dirname(__file__),
                "..", "..", "..", "sift-guard", "dist", "index.js"
            )
        ],
        "env": {
            "T3_INVESTIGATOR_PRIVATE_KEY": os.environ["T3_INVESTIGATOR_PRIVATE_KEY"],
            "T3_NETWORK_ENDPOINT":         os.environ["T3_NETWORK_ENDPOINT"],
        },
    },
}
```

### Step 2 — Add two helper methods to the investigation controller

Open `sift-agent/agent_sdk/investigation_controller.py` and add these two methods to your `InvestigationController` class:

```python
async def seal_phase_in_tee(
    self,
    phase: str,
    specialist_name: str,
    findings_summary: str,
) -> None:
    await self.run_tool(
        "sift-guard",
        "custody_seal",
        {
            "case_id":          self.case_id,
            "evidence_hash":    self.case_state.evidence_hash,
            "phase":            phase,
            "specialist_name":  specialist_name,
            "findings_summary": findings_summary,
        },
    )

async def issue_custody_certificate(self, report_summary: str) -> dict:
    result = await self.run_tool(
        "sift-guard",
        "issue_vc",
        {
            "case_id":        self.case_id,
            "evidence_hash":  self.case_state.evidence_hash,
            "report_summary": report_summary,
        },
    )
    return result
```

### Step 3 — Call seal after each phase

Find where each phase finishes in `investigation_controller.py` and add a seal call immediately after:

```python
async def run_analyze_phase(self):
    for specialist in self.selected_specialists:
        result = await self.run_specialist(specialist)
        await self.seal_phase_in_tee(
            phase="analyze",
            specialist_name=specialist.name,
            findings_summary=result.one_line_summary,
        )

async def run_attribute_phase(self):
    result = await self.run_specialist(self.attack_map_specialist)
    await self.seal_phase_in_tee(
        phase="attribute",
        specialist_name="attack_map",
        findings_summary=result.one_line_summary,
    )

async def run_report_phase(self):
    report = await self.report_synthesizer.generate(self.case_state)
    certificate = await self.issue_custody_certificate(
        report_summary=report.executive_summary
    )
    self.audit_logger.log_certificate(certificate)
```

### Step 4 — Add T3 environment variables to SIFT's `.env`

Open `sift-agent/.env` and append:

```
T3_INVESTIGATOR_PRIVATE_KEY=0xyour_ethereum_private_key_here
T3_NETWORK_ENDPOINT=https://sandbox.terminal3.io
```

---

## MCP Tools Reference

sift-guard exposes three tools over stdio MCP. SIFT calls them the same way it calls any other MCP tool.

### `custody_seal`

Seals a single investigation phase into the T3 TEE. Call after each specialist completes.

| Parameter | Type | Description |
|---|---|---|
| `case_id` | string | Unique case identifier e.g. `incident-001` |
| `evidence_hash` | string | SHA-256 hash of the evidence file |
| `phase` | enum | `acquire` · `hash` · `analyze` · `attribute` · `report` |
| `specialist_name` | string | Name of the SIFT specialist that just ran |
| `findings_summary` | string | One-line summary of what was found |

Returns:
```json
{
  "sealed": true,
  "map_key": "custody:incident-001:analyze:filesystem",
  "sealed_at": "2026-06-21T14:32:01.000Z",
  "message": "Phase 'analyze' sealed in T3 TEE for case incident-001"
}
```

---

### `custody_get`

Retrieves the full sealed custody chain for a case. Use this to verify or export the record.

| Parameter | Type | Description |
|---|---|---|
| `case_id` | string | Unique case identifier |

Returns:
```json
{
  "case_id": "incident-001",
  "custody_chain": [
    {
      "phase": "analyze",
      "specialist_name": "filesystem",
      "evidence_hash": "a3f8c2...",
      "findings_summary": "Found 3 suspicious executables in /tmp",
      "sealed_at": "2026-06-21T14:32:01.000Z"
    }
  ]
}
```

---

### `issue_vc`

Issues a hardware-signed verifiable credential from the T3 TEE. Call once at the end of the investigation after the report is written.

| Parameter | Type | Description |
|---|---|---|
| `case_id` | string | Unique case identifier |
| `evidence_hash` | string | Final SHA-256 hash of the evidence |
| `report_summary` | string | One-paragraph summary of findings |

Returns:
```json
{
  "issued": true,
  "case_id": "incident-001",
  "verifiable_credential": {
    "type": "ForensicChainOfCustody",
    "proof": "...",
    "issued_at": "2026-06-21T15:00:00.000Z"
  },
  "message": "Court-admissible chain-of-custody credential issued from T3 TEE"
}
```

---

## Full investigation flow

```
python main.py --case-id incident-001 --evidence /home/you/evidence.dd
│
├── acquire phase
│     └── sift-guard custody_seal (phase: acquire)
│
├── hash gate ✓
│
├── analyze phase
│     ├── filesystem specialist → sift-guard custody_seal (phase: analyze)
│     ├── carver specialist     → sift-guard custody_seal (phase: analyze)
│     ├── malware specialist    → sift-guard custody_seal (phase: analyze)
│     └── reversing specialist  → sift-guard custody_seal (phase: analyze)
│
├── attribute phase
│     ├── attack_map specialist → sift-guard custody_seal (phase: attribute)
│     └── defense_map specialist → sift-guard custody_seal (phase: attribute)
│
├── attribution gate ✓
│
└── report phase
      ├── report_synthesizer generates report
      └── sift-guard issue_vc → court-admissible certificate
```

---

## Verify a certificate

Anyone with the certificate JSON can verify it independently at:

```
https://verify.terminal3.io
```

Paste the `verifiable_credential` field from `issue_vc` output. No account needed.

---

## Project structure

```
sift-guard/
├── src/
│   └── index.ts          MCP server — three tools over stdio
├── dist/                 compiled output (after npm run build)
├── package.json
├── tsconfig.json
├── .env.example
├── SIFT_INTEGRATION.py   copy-paste snippets for SIFT
└── README.md
```

---

## License

MIT
