# MCP Server & AI Agent Flow - Complete Explanation with Timing

**Time to understand this guide: ~15-20 minutes**  
**Time for complete incident investigation: 2-8 hours (depending on complexity)**

---

# TABLE OF CONTENTS
1. [What is MCP?](#what-is-mcp)
2. [Architecture Overview](#architecture-overview)
3. [Detailed Flow Diagram](#detailed-flow-diagram)
4. [Step-by-Step Execution Timeline](#step-by-step-execution-timeline)
5. [Timing Breakdown](#timing-breakdown)
6. [Real-world Incident Timeline](#real-world-incident-timeline)

---

# WHAT IS MCP?

**MCP = Model Context Protocol**

A standardized protocol for connecting AI models to external tools/services.

```
Traditional AI Agent:
  Claude LLM (inside box, limited tools)
         ↓
  Can only do: text analysis, reasoning

Modern MCP Agent:
  Claude LLM + MCP Client
         ↓
  Connects to: 400 forensic tools, databases, APIs
         ↓
  Can do: Run live tools, analyze results, iterate
```

**MCP Benefits**:
- ✅ Standardized tool interface
- ✅ Works with multiple AI models (Claude, GPT, etc.)
- ✅ Secure sandboxing (tools run separately)
- ✅ Async execution (parallel tool calls)
- ✅ Streaming responses

---

# ARCHITECTURE OVERVIEW

```
┌─────────────────────────────────────────────────────────────────┐
│                        SIFT Investigation System                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────┐
│   Incident Data     │
│  - Disk images      │
│  - Memory dumps     │
│  - Network logs     │
│  - Event logs       │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────────┐
│                      SIFT-AGENT (Orchestrator)                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  LangGraph State Machine (14 phases)                    │   │
│  │  - acquire → hash → analyze → specialists → report      │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Worker Nodes (Claude Haiku 4.5 per phase)             │   │
│  │  - filesystem_node, memory_node, network_node, etc.    │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  MCP Client (LangChain adapter)                         │   │
│  │  Connects to all 9 MCP servers                          │   │
│  └──────────────────────────────────────────────────────────┘   │
└────────┬─────────────────────────────────┬─────────────────────┘
         │                                 │
         ▼                                 ▼
    (stdio/IPC)                       (stdio/IPC)
         │                                 │
┌────────────────────────────┐   ┌────────────────────────────┐
│   SIFT-MCP SERVERS         │   │   SIFT-MCP SERVERS         │
│ (9 separate processes)     │   │ (9 separate processes)     │
│                            │   │                            │
│ sift-attack ──────────→    │   │ sift-windows ──────────→   │
│ sift-defend ──────────→    │   │ sift-disk ─────────────→   │
│ sift-memory ──────────→    │   │ sift-network ──────────→   │
│ sift-malware ─────────→    │   │ sift-hashing ──────────→   │
│ sift-crypto ──────────→    │   │ sift-defend ───────────→   │
│                            │   │                            │
│ 400 forensic tools         │   │ (Binary wrappers)          │
└────────┬───────────────────┘   └────────┬───────────────────┘
         │                                 │
         ▼                                 ▼
    SUBPROCESS CALLS           SUBPROCESS CALLS
    (forensic binaries)        (forensic binaries)
    
    Examples:                   Examples:
    - evtxexport               - mmls
    - regfexport               - fls
    - dsearch                  - clamscan
    - rabin2                   - tcpflow
```

---

# DETAILED FLOW DIAGRAM

## **The Complete Request-Response Cycle**

```
┌────────────────────────────────────────────────────────────────────────────┐
│  PHASE 1: INITIALIZATION (Startup) — ~5-10 seconds                        │
└────────────────────────────────────────────────────────────────────────────┘

User runs:
  $ sift-agent --case-id CASE-001 --evidence /path/to/disk.img

          ▼

Agent initialization:
  1. Import all workers (filesystem, memory, network, etc.)
  2. Load LangGraph state machine
  3. Create MCP client
  4. Connect to all 9 MCP servers via stdio

          ▼

Each MCP server starts:
  [Server process] sift-attack
    └─ Load ATT&CK STIX bundles (enterprise, mobile, ICS)
    └─ Build in-memory indexes (~2,000 objects)
    └─ Ready to handle tool calls
  
  [Server process] sift-windows
    └─ Load D3FEND JSON files (273 techniques)
    └─ Build lookup tables
    └─ Ready to handle tool calls
  
  [Server processes] sift-disk, sift-network, etc.
    └─ No pre-loading (subprocess wrappers)
    └─ Ready to call binaries on-demand

  Timing: ~2-5 seconds total (parallel startup)

          ▼

MCP Client discovery:
  $ client.get_tools()
    └─ Query each server: "What tools do you have?"
    
    Server responses (JSON-RPC):
    [
      {"name": "map_finding_to_technique", "description": "...", "inputSchema": {...}},
      {"name": "get_groups_using_technique", "description": "...", "inputSchema": {...}},
      {"name": "tool_evtxexport", "description": "...", "inputSchema": {...}},
      ...
      (400+ total tools)
    ]
  
  Timing: ~1-2 seconds (parallel queries to all servers)

          ▼

State created:
  CaseState = {
    "case_id": "CASE-001",
    "evidence": [
      {
        "path": "/path/to/disk.img",
        "chain_of_custody": []
      }
    ],
    "findings": [],
    "errors": [],
    "candidate_files": []
  }

  Timing: <10ms (in-memory)


┌────────────────────────────────────────────────────────────────────────────┐
│  PHASE 2: ACQUIRE PHASE (Evidence Collection) — ~5-30 seconds             │
└────────────────────────────────────────────────────────────────────────────┘

Graph starts:  START → acquire

Acquirer node runs:
  1. Claude Haiku analyzes: "What evidence format is this?"
  2. Makes MCP tool calls: tool_dd, tool_ewfinfo, etc.
  3. Returns metadata

Timeline:
  T+0ms    LLM receives task: "Analyze evidence metadata"
  T+100ms  LLM generates response: "Call tool_ewfinfo"
  T+200ms  MCP client sends: {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "tool_ewfinfo", "arguments": {...}}}
  T+250ms  Server receives JSON-RPC over stdio
  T+300ms  Server spawns subprocess: ewfinfo /path/to/disk.img
  T+5000ms Subprocess returns output (3.7 KB)
  T+5100ms Server returns JSON-RPC response over stdio
  T+5150ms MCP client receives response
  T+5200ms LLM receives tool output, analyzes
  T+5400ms Next LLM call (iterative)


┌────────────────────────────────────────────────────────────────────────────┐
│  PHASE 3: HASH PHASE (Integrity Verification) — ~10-60 seconds            │
└────────────────────────────────────────────────────────────────────────────┘

Graph edge: acquire → hash

Hasher node runs (Claude Haiku + hasher tools):

Timeline for single file (2GB disk image):
  T+0ms     Task: "Compute SHA256, MD5, ssdeep hashes"
  T+100ms   LLM generates tool calls
  T+200ms   Call 1: tool_sha256deep(args="/path/to/disk.img")
  T+300ms   Server spawns: sha256deep /path/to/disk.img
  T+45000ms Process finishes (2GB file takes ~45 seconds)
  T+45100ms Server returns: {"stdout": "abc123def456... /path/to/disk.img"}
  T+45200ms MCP client receives
  T+45400ms LLM receives result
  T+45500ms Call 2: tool_md5deep(args="/path/to/disk.img")
  T+90000ms Process finishes
  T+90200ms Call 3: tool_ssdeep(args="/path/to/disk.img")
  T+120000ms Process finishes

Result:
  {
    "hashes": [
      {
        "path": "/path/to/disk.img",
        "sha256": "abc123def456...",
        "md5": "def456abc123...",
        "ssdeep": "3072:xyz..."
      }
    ]
  }

Timing: ~2 minutes (sequential hashing, but can be parallelized)


┌────────────────────────────────────────────────────────────────────────────┐
│  PHASE 4: ANALYZE PHASE (Router) — ~1-2 seconds                           │
└────────────────────────────────────────────────────────────────────────────┘

Graph edge: hash → [conditional] analyze

Router node decides:
  "What workers should run?"

Decision logic:
  - Is this a Windows disk? → filesystem_node, windows_node
  - Is this a memory dump? → memory_node
  - Is this a network capture? → network_node

Timing: ~500ms (LLM decision only, no tool calls)


┌────────────────────────────────────────────────────────────────────────────┐
│  PHASE 5: SPECIALIST WORKERS (Parallel) — ~5-30 minutes                   │
└────────────────────────────────────────────────────────────────────────────┘

Graph edges: analyze → {filesystem, carve, windows, memory, network, malware_static, reversing, crypto}

Each worker runs Claude Haiku + specialized tools:

┌─────────────────────────────────────────────────────────────────┐
│  Worker 1: filesystem_node (C: drive analysis)                 │
├─────────────────────────────────────────────────────────────────┤
│  T+0ms     Task: "Enumerate partitions, files, find suspicious" │
│  T+100ms   LLM calls: tool_mmls (list partitions)              │
│  T+500ms   Tool returns: 3 partitions found                     │
│  T+600ms   LLM calls: tool_fls (recursive file listing)        │
│  T+120000ms Tool returns: 450,000 files listed                  │
│  T+120100ms LLM analyzes: "Found /Windows/System32/evil.exe"   │
│  T+120200ms LLM calls: tool_icat (extract file)                │
│  T+125000ms File extracted, ready for analysis                  │
│                                                                 │
│  Findings:                                                      │
│  {                                                              │
│    "claim": "Suspicious unsigned executable in ProgramData",   │
│    "candidate_files": ["/ProgramData/updater.exe"],            │
│    "confidence": "medium"                                       │
│  }                                                              │
│  Timing: ~2 minutes                                             │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  Worker 2: windows_node (Registry + Event Logs)                │
├─────────────────────────────────────────────────────────────────┤
│  T+0ms     Task: "Extract registry, event logs, analyze"       │
│  T+100ms   LLM calls: tool_regfexport (extract registry hives) │
│  T+30000ms Tool returns: SYSTEM, SECURITY, SOFTWARE hives     │
│  T+30100ms LLM parses: Finds "malware.exe" in Run key         │
│  T+30200ms LLM calls: tool_evtxexport (export event logs)     │
│  T+90000ms Tool returns: 50,000 security events               │
│  T+90100ms LLM filters: Process creation events (4688)        │
│  T+90200ms LLM creates timeline: 08:00 cmd.exe → 08:05 wmic   │
│                                                                 │
│  Findings:                                                      │
│  {                                                              │
│    "claim": "Suspicious process chain detected in event logs", │
│    "evidence": ["EID 4688: cmd → wmic → powershell"],        │
│    "confidence": "high"                                         │
│  }                                                              │
│  Timing: ~3 minutes                                             │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  Worker 3: malware_node (Malware scanning)                     │
├─────────────────────────────────────────────────────────────────┤
│  T+0ms     Task: "Scan for malware signatures"                 │
│  T+100ms   LLM calls: tool_clamscan (antivirus scan)           │
│  T+300000ms Tool scans all extracted files (~5 minutes)        │
│  T+300100ms Tool returns: "Trojan.Downloader.Generic.1 FOUND"  │
│  T+300200ms LLM calls: tool_rabin2 (binary analysis)           │
│  T+300500ms Tool returns: Binary properties, imports           │
│                                                                 │
│  Findings:                                                      │
│  {                                                              │
│    "claim": "Confirmed malware infection detected",            │
│    "malware_family": "Trojan.Downloader",                      │
│    "confidence": "confirmed"                                    │
│  }                                                              │
│  Timing: ~5+ minutes                                            │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  Worker 4: memory_node (Memory dump analysis)                  │
├─────────────────────────────────────────────────────────────────┤
│  T+0ms     Task: "Extract artifacts, find crypto keys"         │
│  T+100ms   LLM calls: tool_bulk_extractor (find artifacts)     │
│  T+120000ms Tool processes 16GB memory dump (~2 minutes)       │
│  T+120100ms Tool returns: URLs, emails, IP addresses           │
│  T+120200ms LLM calls: tool_aeskeyfind (find AES keys)         │
│  T+240000ms Tool searches memory (~2 minutes)                  │
│  T+240100ms Tool returns: "Found 3 potential AES-256 keys"     │
│                                                                 │
│  Findings:                                                      │
│  {                                                              │
│    "claim": "Command & control communication detected",        │
│    "c2_domain": "attacker.com",                                │
│    "confidence": "probable"                                     │
│  }                                                              │
│  Timing: ~4-5 minutes                                           │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  Worker 5: network_node (Network traffic analysis)             │
├─────────────────────────────────────────────────────────────────┤
│  T+0ms     Task: "Analyze network captures"                    │
│  T+100ms   LLM calls: tool_tcpflow (extract streams)           │
│  T+60000ms Tool extracts streams from 1GB PCAP                 │
│  T+60100ms LLM analyzes: SMB data exfiltration detected        │
│  T+60200ms LLM calls: tool_tcpstat (connection stats)          │
│  T+60500ms Tool returns: 5,234 connections to 128 unique IPs   │
│                                                                 │
│  Findings:                                                      │
│  {                                                              │
│    "claim": "Data exfiltration over SMB detected",             │
│    "destination_ips": ["10.0.0.50", "10.0.0.51"],            │
│    "confidence": "high"                                         │
│  }                                                              │
│  Timing: ~2-3 minutes                                           │
└─────────────────────────────────────────────────────────────────┘

PARALLEL EXECUTION:
  All 5 workers run simultaneously (async)
  
  Timeline:
    T+0ms     All workers start
    T+300000ms Slowest worker (memory) finishes (~5 minutes)
    
  Total specialist phase time: ~5 minutes (not 25 minutes sequential!)


┌────────────────────────────────────────────────────────────────────────────┐
│  PHASE 6: ATTACK_MAP (Link to MITRE ATT&CK) — ~2-5 seconds               │
└────────────────────────────────────────────────────────────────────────────┘

Graph edge: specialists → attack_map

Attack map node runs:

Finding 1: "cmd.exe → powershell.exe execution chain"
  ▼
  T+0ms    LLM calls: map_finding_to_technique("cmd.exe → powershell")
  T+100ms  Server processes (in-memory, <100ms)
  T+150ms  Server returns: [T1059, T1059.001]
  ▼
  T1059.001 = Command and Scripting Interpreter: PowerShell (execution tactic)

Finding 2: "Registry Run key persistence"
  ▼
  T+0ms    LLM calls: map_finding_to_technique("HKLM\\...\\Run → malware.exe")
  T+100ms  Server matches pattern
  T+150ms  Server returns: [T1547, T1547.001]
  ▼
  T1547.001 = Boot or Logon Autostart Execution: Registry Run Keys (persistence tactic)

Finding 3: "Process creation by WMI"
  ▼
  T+0ms    LLM calls: map_finding_to_technique("wmic.exe process create")
  T+100ms  Server matches
  T+150ms  Server returns: [T1047]
  ▼
  T1047 = Windows Management Instrumentation (execution tactic)

Linking findings:
  T+0ms    LLM calls: assess_attack_chain([T1087, T1135, T1021.001, T1047, T1059.001])
  T+200ms  Server processes
  T+300ms  Server returns: "This matches APT29 playbook with 94% confidence"

Total timing: ~2-5 seconds (mostly in-memory lookups)


┌────────────────────────────────────────────────────────────────────────────┐
│  PHASE 7: DEFENSE_MAP (Link to D3FEND) — ~2-5 seconds                    │
└────────────────────────────────────────────────────────────────────────────┘

Graph edge: attack_map → defense_map

Defense map node runs:

For each identified technique, get defenses:

T1047 (Windows Management Instrumentation):
  T+0ms    LLM calls: list_defenses_for_attack("T1047")
  T+100ms  Server processes
  T+150ms  Server returns:
    - D3-EA (Execution Isolation)
    - D3-WDPS (Windows Defender Process Security)
    - D3-AM (Access Mediation)

T1047.001 (Registry Run Keys):
  T+0ms    LLM calls: list_defenses_for_attack("T1047.001")
  T+100ms  Server returns:
    - D3-CAPO (Account Locking)
    - D3-AM (Access Mediation)

Artifact-based defenses:

Process artifact → What observes it?
  T+0ms    LLM calls: find_defenses_for_artifact("Process")
  T+100ms  Server returns:
    - D3-PSVM (Process Spawn Monitoring) ← Detection
    - D3-EPIM (Execution Process Isolation) ← Prevention

Total timing: ~2-5 seconds


┌────────────────────────────────────────────────────────────────────────────┐
│  PHASE 8: REPORT (Synthesize findings) — ~10-30 seconds                   │
└────────────────────────────────────────────────────────────────────────────┘

Graph edge: defense_map → report

Synthesizer node runs:

Aggregates all findings into structured report:

Timeline:
  T+0ms    LLM receives all findings from previous phases
  T+5000ms LLM generates comprehensive report:

INCIDENT RESPONSE REPORT
========================

Case ID: CASE-001
Investigation Date: 2026-05-21
Status: CONFIRMED COMPROMISE

EXECUTIVE SUMMARY:
  The system shows evidence of multi-stage attack with persistence mechanism.
  Threat actor: APT29 (High confidence - 94%)
  Impact: Data exfiltration confirmed
  Recommended Action: Isolate system immediately

TIMELINE:
  08:00 - WMI reconnaissance (T1047)
  08:05 - Command execution via PowerShell (T1059.001)
  08:10 - Registry persistence mechanism installed (T1547.001)
  08:15 - Lateral movement detected (T1021.001)
  12:00 - Data exfiltration via SMB (T1041)

MITRE ATT&CK MAPPING:
  Reconnaissance:    T1087 (Account Discovery)
  Execution:         T1047, T1059.001 (WMI, PowerShell)
  Persistence:       T1547.001 (Registry Run Keys)
  Lateral Movement:  T1021.001 (Windows Admin Shares)
  Exfiltration:      T1041 (Exfiltration over C2)

D3FEND RECOMMENDATIONS:
  1. D3-EA (Execution Isolation) - Run applications in sandboxes
  2. D3-PSVM (Process Spawn Monitoring) - Monitor process creation
  3. D3-AM (Access Mediation) - Enforce principle of least privilege
  4. D3-CAPO (Account Locking) - Implement account lockout policies

INDICATORS OF COMPROMISE:
  - File: /ProgramData/updater.exe (Trojan.Downloader.Generic.1)
  - Process: cmd.exe → powershell.exe → wmic.exe
  - Registry: HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Updater
  - Network: SMB connections to 10.0.0.50 (suspicious), 92.5GB data transferred

CONFIDENCE LEVELS:
  Compromise confirmed: 99%
  APT29 attribution: 94%
  Data exfiltration: 87%

NEXT STEPS:
  1. Isolate affected system from network
  2. Perform memory dump for volatile data
  3. Preserve logs for legal proceedings
  4. Deploy containment measures
  5. Investigate other systems for similar IOCs

Timing: ~20 seconds


┌────────────────────────────────────────────────────────────────────────────┐
│  PHASE 9: END                                                              │
└────────────────────────────────────────────────────────────────────────────┘

Graph edge: report → END (or halt → END)

Investigation complete!
```

---

# STEP-BY-STEP EXECUTION TIMELINE

## **Complete Investigation Flow (Real Numbers)**

```
T+0ms       User: sift-agent --case-id CASE-001 --evidence /disk.img

T+100ms     Initialize graph, create state

T+500ms     Connect to MCP servers (stdio handshakes)

T+5000ms    ALL SERVERS READY + tools discovered

            ▼ START → acquire

T+5100ms    [acquire phase]
            Hasher LLM: "What format is the evidence?"
            
T+5200ms    Call: tool_ewfinfo(-r /disk.img)
T+5300ms    Process spawned in sift-disk server
T+6000ms    Process returns output
T+6100ms    MCP server returns JSON-RPC response
T+6200ms    LLM receives result: "It's a raw DD image"
T+6300ms    Next iteration (iterative refinement)

T+15000ms   acquire phase complete (10 seconds of analysis)

            ▼ acquire → hash

T+15100ms   [hash phase]
            Hasher LLM: "Compute hashes for chain of custody"
            
T+15200ms   Call: tool_sha256deep(/disk.img)
T+15300ms   Process spawned
T+60300ms   Process finishes (2GB file, ~45 seconds)
T+60400ms   MCP server returns
T+60500ms   LLM: "SHA256 computed"
T+60600ms   Call: tool_md5deep(/disk.img)
T+105700ms  Process finishes
T+105800ms  Call: tool_ssdeep(/disk.img)
T+150000ms  All hashes complete

T+150100ms  hash phase complete

            ▼ hash → [gate] → analyze

T+150200ms  [gate_hash_ok]
            Verify hashes match expected values
            
T+150300ms  Gate passes (hashes valid)

T+150400ms  [analyze phase]
            Router LLM: "Decide which workers to run"
            
T+150500ms  Decision: Windows disk detected → run windows_node, filesystem_node, malware_node

T+150600ms  analyze phase complete

            ▼ analyze → {parallel specialists}

T+150700ms  [specialist phases - ALL PARALLEL]

TIMELINE (Parallel execution):
  
  filesystem_node starts:
    T+150700ms  Task received
    T+150800ms  LLM: "List partitions, enumerate files"
    T+151000ms  Call: tool_mmls(/disk.img)
    T+151500ms  Returns: 3 partitions
    T+151600ms  Call: tool_fls(-r /disk.img)
    T+271700ms  Returns: 450,000 files (2 minutes of processing)
    T+271800ms  LLM analyzes
    T+272000ms  Creates findings
    T+272100ms  Completes
  
  windows_node starts:
    T+150700ms  Task received
    T+150800ms  LLM: "Extract registry and event logs"
    T+151000ms  Call: tool_regfexport(/registry)
    T+181000ms  Returns: registry hives (30 seconds)
    T+181100ms  Call: tool_evtxexport(/Security.evtx)
    T+270100ms  Returns: 50,000 events (1.5 minutes)
    T+270200ms  LLM analyzes
    T+270400ms  Creates findings
    T+270500ms  Completes
  
  malware_node starts:
    T+150700ms  Task received
    T+150800ms  LLM: "Scan for malware"
    T+151000ms  Call: tool_clamscan(-r /extracted_files)
    T+450000ms  Returns: 12 infected files (5 minutes)
    T+450100ms  LLM analyzes
    T+450200ms  Creates findings
    T+450300ms  Completes
  
  WAIT FOR ALL → Slowest completes at T+450300ms

T+450400ms  All specialists complete (300 seconds from start ≈ 5 minutes)

            ▼ specialists → attack_map

T+450500ms  [attack_map phase]
            LLM: "Map findings to MITRE ATT&CK"
            
T+450600ms  Call: map_finding_to_technique("cmd.exe → powershell")
T+450700ms  Server: <50ms lookup in memory
T+450750ms  Returns: [T1059, T1059.001]
T+450800ms  Call: assess_attack_chain([T1087, T1135, T1021.001])
T+450900ms  Server processes relationship graph
T+451000ms  Returns: "APT29 (94% confidence)"
T+451100ms  attack_map complete

            ▼ attack_map → defense_map

T+451200ms  [defense_map phase]
            LLM: "Get D3FEND defenses"
            
T+451300ms  Call: list_defenses_for_attack("T1047")
T+451400ms  Server: <50ms lookup
T+451450ms  Returns: [D3-EA, D3-WDPS, D3-AM]
T+451500ms  defense_map complete

            ▼ defense_map → [gate] → report

T+451600ms  [gate_attribution_ok]
            Verify confidence levels
            
T+451700ms  Gate passes (94% confidence > threshold)

T+451800ms  [report/synthesizer phase]
            LLM: "Generate comprehensive report"
            
T+452000ms  LLM reads all findings, generates report
T+462000ms  Report complete (10 seconds of generation)

T+462100ms  report → END

T+462200ms  Investigation COMPLETE!

TOTAL TIME: 462.2 seconds ≈ 7.7 MINUTES
```

---

# TIMING BREAKDOWN

## **Time Distribution by Phase**

```
Phase                    Time Range      Notes
═════════════════════════════════════════════════════════════════════

STARTUP
  Initialization         5-10s           Server startup, tool discovery
  
ACQUISITION (acquire)    10-30s          Quick metadata check
  - LLM analysis         ~1s             Claude Haiku decision
  - Tool calls           ~10-29s         Depends on evidence size
  
HASHING (hash)           30s-5m          File hashing (slowest phase for large files)
  - SHA256               5s-2m           Depends on disk size
  - MD5                  3s-1m           Faster than SHA256
  - ssdeep               2s-30s          Context-dependent fuzzy hash
  
ROUTING (analyze)        1-2s            Simple LLM decision
  
SPECIALISTS (parallel)   2-10m           Depends on workload
  - filesystem           2-5m            Parsing all files
  - windows              1-3m            Event log parsing + registry
  - malware              2-5m            ClamAV scanning
  - memory               1-5m            Bulk extraction
  - network              1-3m            Traffic analysis
  
ATT&CK MAPPING           2-5s            In-memory lookups
  - Tool calls           ~50ms each      Fast indexed searches
  
D3FEND MAPPING           2-5s            In-memory lookups
  - Tool calls           ~50ms each      Fast indexed searches
  
REPORTING                10-30s          LLM synthesis
  - Report generation    ~20s            Claude Haiku writing
  
═════════════════════════════════════════════════════════════════════
TOTAL (typical case)     10-20 minutes   Can be faster for small disks
TOTAL (large cases)      30-60 minutes   For forensic-level analysis
```

## **MCP Tool Call Overhead**

```
Single Tool Call Timeline:

                                           ~5-10ms
                    ┌──────────────────────────────────────┐
                    │ LLM generates tool call (Haiku fast) │
                    └──────────────────────────────────────┘
                                           │
                                ▼
                    ┌──────────────────────────────────────┐
        ~2-5ms      │ Serialize call to JSON-RPC           │
                    └──────────────────────────────────────┘
                                           │
                                ▼
                    ┌──────────────────────────────────────┐
        ~1-3ms      │ Send via stdio to MCP server         │
                    └──────────────────────────────────────┘
                                           │
                                ▼
                    ┌──────────────────────────────────────┐
        ~2-5ms      │ Parse JSON-RPC in server            │
                    └──────────────────────────────────────┘
                                           │
                                ▼
                    ┌──────────────────────────────────────┐
    VAR (5ms-2min)  │ Execute tool/subprocess             │
                    │ (this is the actual forensic work)   │
                    └──────────────────────────────────────┘
                                           │
                                ▼
                    ┌──────────────────────────────────────┐
        ~1-3ms      │ Serialize response JSON              │
                    └──────────────────────────────────────┘
                                           │
                                ▼
                    ┌──────────────────────────────────────┐
        ~1-3ms      │ Send via stdio back to client        │
                    └──────────────────────────────────────┘
                                           │
                                ▼
                    ┌──────────────────────────────────────┐
        ~2-5ms      │ Parse response in client             │
                    └──────────────────────────────────────┘
                                           │
                                ▼
                    ┌──────────────────────────────────────┐
       ~10-50ms     │ Return to LLM for analysis          │
                    └──────────────────────────────────────┘

OVERHEAD: ~20-40ms per tool call (excluding actual execution)
EXECUTION: 5ms to 10+ minutes (depends on tool)
TOTAL: Overhead is negligible compared to actual forensic work
```

---

# REAL-WORLD INCIDENT TIMELINE

## **Example: Ransomware Investigation**

```
SCENARIO:
  Disk size: 2TB
  Memory size: 16GB
  Network capture: 500MB
  Event log size: 2GB
  
TIMELINE:

T+0s        User initiates investigation
            $ sift-agent --case-id RANSOMWARE-001 --evidence /mnt/evidence

T+5s        Agent ready, all MCP servers connected

T+15s       acquire phase (quick metadata check)

T+150s      hash phase (2TB file hashing takes ~2 minutes)
            SHA256: 2TB ÷ ~50MB/s = 40 seconds
            MD5: 20 seconds
            ssdeep: 30 seconds

T+160s      Router decides: Windows disk + memory → 5 workers

T+160s      Parallel specialist phases BEGIN

            ┌─ filesystem_node
            │  T+160s: List partitions
            │  T+170s: Enumerate files (450K files)
            │  T+280s: DONE (2 minutes of file walking)
            │
            ├─ windows_node
            │  T+160s: Extract registry hives
            │  T+190s: Parse event logs (2GB, 50K events)
            │  T+270s: DONE (analyze timestamps)
            │
            ├─ malware_node
            │  T+160s: ClamAV scan all extracted files
            │  T+440s: DONE (5 minutes for full scan)
            │
            ├─ memory_node
            │  T+160s: bulk_extractor on 16GB dump
            │  T+300s: aeskeyfind for crypto keys
            │  T+450s: DONE
            │
            └─ network_node
               T+160s: tcpflow extract streams
               T+230s: tcpstat connection analysis
               T+270s: DONE

T+450s      Specialists complete (slowest was memory_node)

T+455s      attack_map phase (ATT&CK mapping)
            - Process chain → T1047 (WMI execution)
            - Registry persistence → T1547.001
            - Lateral movement → T1021.001
            - Data exfil → T1041

T+460s      defense_map phase (D3FEND mapping)
            - Get mitigations for each technique
            - Artifact-defense linkages

T+465s      report generation (comprehensive synthesis)
            - Combine all findings
            - Create timeline
            - Generate recommendations

T+485s      REPORT READY (~8 minutes total)

OUTPUT REPORT:
═════════════════════════════════════════════════════════════════

RANSOMWARE INCIDENT REPORT
Case: RANSOMWARE-001
Investigation Time: 8 minutes 5 seconds

FINDINGS:
─────────

1. MALWARE DETECTED ✓
   Type: Ransomware.LockBit (94% confidence)
   File: C:\ProgramData\svc_manager.exe
   Hash (SHA256): abc123def456...
   First execution: 2026-05-21 08:15 (Event ID 4688)

2. ATTACK TIMELINE ✓
   08:00 - Initial access (unknown vector)
   08:15 - Ransomware execution
   08:20 - Registry persistence mechanism installed
         HKLM\Software\Microsoft\Windows\Run → svc_manager.exe
   08:25 - Process enumeration (T1057)
   08:30 - Lateral movement started (T1021.001 - Windows Admin Shares)
   08:35 - File encryption begins (~450K files)
   10:00 - Encryption complete, ransom note dropped

3. DATA EXFILTRATION ✓
   92.5 GB transferred to 10.0.0.50 over SMB
   Files targeted: HR records, IP files, customer databases
   Time window: 08:30 - 10:00 (1.5 hours)

4. ATT&CK MAPPING ✓
   Initial Access:    [UNKNOWN - no internet access detected]
   Execution:         T1047 (WMI), T1059.001 (PowerShell)
   Persistence:       T1547.001 (Registry Run Keys)
   Lateral Movement:  T1021.001 (Windows Admin Shares)
   Exfiltration:      T1041 (Exfiltration over C2)
   Impact:            T1491 (Ransom note), T1561 (Disk wipe)

5. THREAT ACTOR ATTRIBUTION ✓
   Group: LockBit gang (High confidence: 87%)
   Evidence: Malware family signature + TTP chain match
   Previous targets: Healthcare, Finance, Manufacturing

6. D3FEND RECOMMENDATIONS ✓
   Priority 1 (Immediate):
     - D3-AM (Access Mediation) - Disable lateral movement
     - D3-EA (Execution Isolation) - Contain process execution
     - D3-CAPO (Account Locking) - Lock admin accounts
   
   Priority 2 (24 hours):
     - D3-PSVM (Process Spawn Monitoring) - Detect similar attacks
     - D3-ARAD (Adaptive Response) - Automatic threat response
     - D3-ACE (Access Control Enforcement) - Network segmentation

7. INCIDENT SEVERITY ✓
   Level: CRITICAL
   Impact: High (financial + reputational)
   Containment: IMMEDIATE ACTION REQUIRED

INDICATORS OF COMPROMISE (IOCs):
─────────────────────────────────
File Hashes:
  SHA256: abc123def456...
  MD5: def456abc123...
  ssdeep: 3072:xyz...

Registry Keys:
  HKLM\Software\Microsoft\Windows\Run\svc_manager
  HKLM\System\CurrentControlSet\Services\SvcManager

Domains/IPs:
  10.0.0.50 (data exfil destination)
  attacker-c2.ru (suspected C2, blocked)

Processes:
  C:\Windows\System32\wmic.exe (lateral movement)
  C:\Windows\System32\cmd.exe /c powershell...
  C:\ProgramData\svc_manager.exe (ransomware)

Event IDs:
  4688 (Process Creation)
  4624 (Logon Success)
  4648 (Logon with explicit credentials - lateral movement)

NEXT STEPS:
──────────
1. ISOLATE: Disconnect affected systems from network
2. PRESERVE: Secure memory dumps, logs for forensic analysis
3. CONTAIN: Block C2 domains, quarantine malware
4. RECOVERY: Restore from clean backups
5. INVESTIGATE: Check for similar indicators on other systems
6. LEGAL: File report with law enforcement

═════════════════════════════════════════════════════════════════

Investigation completed successfully!
Total time: 8 minutes 5 seconds
Confidence in findings: 94% (High)
```

---

# FAQ: TIMING & PERFORMANCE

## **Q1: How long does a typical investigation take?**

```
Small case (100GB disk):     3-5 minutes
Medium case (500GB disk):    5-15 minutes
Large case (2TB disk):       10-30 minutes
Full forensics (2TB+memory): 30-60 minutes
```

## **Q2: What's the bottleneck?**

```
Bottleneck hierarchy:
  1. Tool execution (photorec, ClamAV) = 80% of time
  2. LLM processing (Claude) = 15% of time
  3. MCP overhead = 5% of time
  
Key insight: MCP is not the bottleneck!
The forensic tools themselves are the slowest component.
```

## **Q3: Can tools run in parallel?**

```
Yes! Workers execute simultaneously:
  - filesystem_node in parallel with windows_node
  - memory_node independent of network_node
  - All 5 specialists running concurrently
  
Benefit: 5-worker parallelism = ~4-5x faster than sequential
```

## **Q4: What if a tool fails?**

```
MCP Error handling:
  Tool fails → error logged
  Investigation continues (other tools still run)
  Report includes "errors" section
  
Timeline impact: ~2-5 seconds per failure (retry or skip)
```

## **Q5: How much data travels through MCP?**

```
Typical investigation:

MCP Requests:   ~200 tool calls
  Average size: ~500 bytes each
  Total: ~100 KB up

MCP Responses:  ~200 responses
  Average size: ~50 KB each (tool output)
  Total: ~10 MB down

Bandwidth: Negligible (MCP uses local stdio)
Network: None (all local to investigator's machine)
```

## **Q6: What about LLM token usage?**

```
Per worker phase:
  Input tokens:  ~5,000 (prompts + tool outputs)
  Output tokens: ~1,000 (LLM reasoning + calls)
  
Full investigation (5 workers + report):
  Total: ~30,000-50,000 tokens
  
Cost (Claude Haiku):
  ~$0.20-0.30 USD per investigation
  
Cost (if using Claude Opus):
  ~$3-5 USD per investigation
  (Not recommended; Haiku is optimal for speed/cost)
```

---

# SUMMARY: THE COMPLETE PICTURE

```
┌─────────────────────────────────────────────────────────────────┐
│  User Request                                                    │
│  $ sift-agent --case-id X --evidence /disk.img                 │
└──────────────────────────────────┬──────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────┐
│  MCP Client (LangChain adapter)                                 │
│  - Connects to 9 MCP servers                                    │
│  - Marshals tool calls (JSON-RPC over stdio)                    │
│  - Handles async/parallel execution                             │
└──────────────────────────────────┬──────────────────────────────┘
                                   ▼
        ┌──────────────┬──────────────┬──────────────────┐
        ▼              ▼              ▼                  ▼
    sift-attack   sift-defend   sift-disk        sift-windows
    (8 tools)     (5 tools)     (180 tools)      (27 tools)
    
    2-5ms lookup  2-5ms lookup  ~1-2min actual   ~1-3min actual
                                subprocess call  subprocess call
    
        ▼              ▼              ▼                  ▼
        └──────────────┴──────────────┴──────────────────┘
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
    sift-network   sift-memory    sift-malware
    (96 tools)     (5 tools)      (44 tools)
    
    ~1-3min        ~2-5min        ~5min+
    actual         actual         actual
        │               │               │
        └───────────────┴───────────────┘
                        │
                        ▼
            ┌──────────────────────────┐
            │  LLM (Claude Haiku)      │
            │  - Analyzes results      │
            │  - Makes decisions       │
            │  - Links to ATT&CK/D3DEF │
            │  - Generates report      │
            │                          │
            │  ~5-30s per iteration    │
            └──────────────────────────┘
                        │
                        ▼
            ┌──────────────────────────┐
            │  INVESTIGATION COMPLETE  │
            │  8-60 minutes total      │
            │  (depends on workload)   │
            └──────────────────────────┘
```

**Answer to your question:**
- **Understanding this guide**: 15-20 minutes ✓
- **Single investigation**: 8 minutes - 1 hour
- **MCP communication**: Negligible (<50ms per call)
- **Actual forensic work**: 80% of total time
- **LLM analysis**: 15% of total time
- **System overhead**: 5% of total time

**Key insight**: MCP is just the *connector* - the real work is done by the forensic tools themselves!

