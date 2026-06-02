# AI AGENT LOGS - Complete Explanation

**Location**: `sift-agent/console_logger.py`  
**Purpose**: Real-time operational tracking + cost calculation during investigation

---

# TABLE OF CONTENTS
1. [ConsoleLogger Architecture](#consolelogger-architecture)
2. [Color Code System](#color-code-system)
3. [Output Format & Fields](#output-format--fields)
4. [Real Log Examples](#real-log-examples)
5. [WorkerStats Tracking](#workerstats-tracking)
6. [Cost Calculation Model](#cost-calculation-model)
7. [Integration with LangGraph](#integration-with-langgraph)
8. [Debugging with Agent Logs](#debugging-with-agent-logs)

---

# CONSOLELOGGER ARCHITECTURE

## Core Components

```python
class ConsoleLogger:
    def __init__(self):
        self._lock = threading.Lock()           # Thread-safe printing
        self.stats: dict[str, WorkerStats] = {} # Track per-worker metrics
        self.opus_agents: set[str] = set()      # Mark expensive agents
        self.current_phase: str = ""             # Track workflow phase

# Cost constants (Claude API pricing)
_HAIKU_IN  = 1.0    # $1 per 1M input tokens
_HAIKU_OUT = 5.0    # $5 per 1M output tokens
_OPUS_IN   = 15.0   # $15 per 1M input tokens
_OPUS_OUT  = 75.0   # $75 per 1M output tokens
```

## WorkerStats Dataclass

```python
@dataclass
class WorkerStats:
    name: str                      # Agent name (e.g., "filesystem")
    tools_called: int = 0          # How many tools executed
    errors: int = 0                # Failed tool calls
    input_tokens: int = 0          # Total LLM input tokens
    output_tokens: int = 0         # Total LLM output tokens
    started_at: str = ""           # HH:MM:SS when agent started
    finished_at: str = ""          # HH:MM:SS when agent finished
```

## Public Methods

```python
# Case lifecycle
log.case_start(case_id: str)         # Print "=== CASE ID ===" header
log.case_done(case_id: str)          # Print completion

# Workflow phases
log.phase(phase: str)                # "acquire", "hash", "filesystem", etc.

# Worker activity
log.agent_start(name: str, doing: str)              # "filesystem - walking disk"
log.agent_done(name: str, tokens_in: int, tokens_out: int)

# Tool execution
log.tool(agent: str, tool: str, exit_code: int|None, duration_ms: int|None)

# Decision gates
log.gate(name: str, decision: str)  # "gate_hash_ok -> ok" or "-> halt"

# Messages
log.error(who: str, msg: str)
log.info(who: str, msg: str)

# Summary
log.summary()                        # Print final stats + cost
```

---

# COLOR CODE SYSTEM

## ANSI Color Codes

```python
C.RESET   = "\033[0m"      # Default color (reset)
C.DIM     = "\033[2m"      # Grayed out / less important
C.BOLD    = "\033[1m"      # Bold text
C.RED     = "\033[31m"     # Red (errors, failures)
C.GREEN   = "\033[32m"     # Green (agents working)
C.YELLOW  = "\033[33m"     # Yellow (tool calls)
C.BLUE    = "\033[34m"     # Blue (info messages)
C.MAGENTA = "\033[35m"     # Magenta (gate decisions)
C.CYAN    = "\033[36m"     # Cyan (case headers, phases)
C.GRAY    = "\033[90m"     # Gray (timestamps)
```

## Usage Pattern

```
┌─────────────────────────────────────────────────────────┐
│ [HH:MM:SS]  [TAG]   AGENT_NAME         MESSAGE           │
│ └─ GRAY    └─ COLOR  └─ BOLD            └─ DIM/NORMAL   │
└─────────────────────────────────────────────────────────┘

Color meanings:
  GRAY     = Timestamp (supporting, not critical)
  [CYAN]   = Case/Phase tags (major milestones)
  [GREEN]  = Agent activity (normal, working)
  [YELLOW] = Tool calls (detailed activity)
  [RED]    = Errors (problems)
  [MAGENTA]= Gates (decision points)
  [BLUE]   = Info (diagnostics)
  BOLD     = Important (agent names, phases)
  DIM      = Supporting (token counts, technical details)
```

---

# OUTPUT FORMAT & FIELDS

## Standard Output Line

```
[HH:MM:SS] [TAG] AGENT_NAME           MESSAGE

Breakdown:
  [HH:MM:SS]     Gray timestamp (self._ts() = datetime.now().strftime("%H:%M:%S"))
  [TAG]          Color-coded tag: Agent|Tool|Phase|Gate|Error|Info
  AGENT_NAME     Bold 16-char agent name (left-aligned padding)
  MESSAGE        The actual content (dim for technical, normal for content)
```

## Examples

```
[10:02:15] [Phase]  acquire
           [Agent] filesystem       - walking 1 disk image(s)
           [Tool]   filesystem       fls                          exit=0 duration=2500ms
           [Agent] filesystem       done   tokens in:8234 out:1456
           [Gate]   gate_hash_ok     -> ok
           [Error]  windows          Registry file not found
           [Info]   synthesizer      Generated 50 findings
```

---

# REAL LOG EXAMPLES

## Example 1: Simple Agent Execution

```
[10:00:15] [Phase]  hash
[10:00:16] [Agent] hasher              - hashing disk image
[10:00:17] [Tool]   hasher              sha256deep                 exit=0 duration=45000ms
[10:00:18] [Tool]   hasher              md5deep                    exit=0 duration=25000ms
[10:45:30] [Agent] hasher              done   tokens in:2345 out:456
```

**What this shows:**
- ✅ Hashing phase started at 10:00:15
- ✅ hasher agent started work at 10:00:16
- ✅ sha256deep ran successfully (exit=0) in 45 seconds
- ✅ md5deep ran successfully (exit=0) in 25 seconds
- ✅ Agent completed after 45+ minutes with 2,345 input tokens, 456 output tokens
- 💰 Cost: (2345 * $1 + 456 * $5) / 1M = $0.0037

---

## Example 2: Tool Failure

```
[10:50:20] [Phase]  windows
[10:50:21] [Agent] windows             - analyzing registry + events
[10:50:22] [Tool]   windows             regfexport                 exit=0 duration=30000ms
[10:50:23] [Tool]   windows             evtxexport                 exit=1 duration=500ms
[10:50:24] [Error]  windows             Event log parsing failed
[10:55:30] [Agent] windows             done   tokens in:6789 out:1234
```

**What this shows:**
- ✅ regfexport succeeded (exit=0)
- ❌ evtxexport failed (exit=1)
- ⚠️  Error logged: "Event log parsing failed"
- ✅ Agent continued despite tool failure and completed successfully
- 📊 windows WorkerStats: errors=1, tools_called=2, input_tokens=6789, output_tokens=1234

---

## Example 3: Gate Decision

```
[05:30:20] [Phase]  analyze
[05:30:21] [Agent] router              - selecting analysis path
[05:30:22] [Gate]   gate_hash_ok        -> ok
[05:30:23] [Phase]  filesystem
...
(alternatively, if gate fails:)
[05:30:22] [Gate]   gate_hash_ok        -> halt
[05:30:23] [Error]  router              Hash verification failed
[05:30:24] [Phase]  halt
```

**What this shows:**
- 🔀 Router decides: is evidence hash valid?
- ✅ Gate passes → continue to filesystem phase
- ❌ Gate fails → halt investigation (exit before workers run)

---

## Example 4: Complete Investigation Log

```
=== CASE RANSOMWARE-001 ===

[00:00:01] [Phase]  acquire
[00:00:02] [Agent] acquirer            - analyzing evidence format
[00:00:05] [Tool]   acquirer            ewfinfo                    exit=0 duration=50ms
[00:00:10] [Agent] acquirer            done   tokens in:1234 out:234

[00:00:11] [Phase]  hash
[00:00:12] [Agent] hasher              - hashing evidence
[00:00:13] [Tool]   hasher              sha256deep                 exit=0 duration=45000ms
[00:00:58] [Tool]   hasher              md5deep                    exit=0 duration=25000ms
[00:45:30] [Agent] hasher              done   tokens in:2345 out:456

[00:45:31] [Phase]  analyze
[00:45:32] [Agent] router              - analyzing case
[00:45:33] [Gate]   gate_hash_ok        -> ok

[00:45:34] [Phase]  filesystem
[00:45:35] [Agent] filesystem          - walking disk image
[00:45:36] [Tool]   filesystem          mmls                       exit=0 duration=50ms
[00:45:37] [Tool]   filesystem          fls                        exit=0 duration=120000ms
[02:45:38] [Tool]   filesystem          icat                       exit=0 duration=1000ms
[02:47:00] [Agent] filesystem          done   tokens in:8234 out:1456

[00:45:34] [Phase]  windows
[00:45:35] [Agent] windows             - analyzing artifacts
[00:45:36] [Tool]   windows             regfexport                 exit=0 duration=30000ms
[01:15:37] [Tool]   windows             evtxexport                 exit=0 duration=60000ms
[02:47:00] [Agent] windows             done   tokens in:6789 out:1234

[00:45:34] [Phase]  malware
[00:45:35] [Agent] malware_static      - scanning signatures
[00:45:36] [Tool]   malware_static      clamscan                   exit=1 duration=300000ms
[05:45:37] [Agent] malware_static      done   tokens in:4521 out:987

[00:45:34] [Phase]  memory
[00:45:35] [Agent] memory              - extracting from dump
[00:45:36] [Tool]   memory              volatility                 exit=0 duration=120000ms
[02:47:00] [Agent] memory              done   tokens in:3456 out:654

[05:45:38] [Phase]  attack_map
[05:45:39] [Agent] attack_mapper       - linking to MITRE
[05:45:40] [Tool]   attack_mapper       map_finding_to_technique   exit=0 duration=50ms
[05:45:41] [Tool]   attack_mapper       assess_attack_chain        exit=0 duration=100ms
[05:45:42] [Agent] attack_mapper       done   tokens in:2345 out:456

[05:45:43] [Phase]  defense_map
[05:45:44] [Agent] defense_mapper      - linking to D3FEND
[05:45:45] [Tool]   defense_mapper      list_defenses_for_attack   exit=0 duration=50ms
[05:45:46] [Agent] defense_mapper      done   tokens in:1234 out:234

[05:45:47] [Phase]  report
[05:45:48] [Agent] synthesizer         - generating report
[06:00:00] [Agent] synthesizer         done   tokens in:5678 out:1234

=== CASE RANSOMWARE-001 COMPLETE ===

=== SUMMARY ===
AGENT                IN        OUT     TOOLS   ERR
acquirer             1234       234         1     0
hasher               2345       456         2     0
router                567        89         1     0
filesystem           8234      1456         3     0
windows              6789      1234         2     0
malware_static       4521       987         1     1
memory               3456       654         1     0
attack_mapper        2345       456         2     0
defense_mapper       1234       234         1     0
synthesizer          5678      1234         1     0
TOTAL               37381      8252        15     1   cost~$0.0365
```

**Timeline Analysis:**

```
Phase Breakdown (milliseconds):
  acquire:     10,000 ms  (0-10s)          – Verify evidence format
  hash:        45,000 ms  (10-55s)         – Fingerprint evidence
  analyze:        100 ms  (55-56s)         – Route to workers
  ───── Parallel workers start here ─────
  filesystem: 120,000 ms  (56-196s)        – Walk disk
  windows:    90,000 ms   (56-146s)        – Extract registry/events
  malware:    300,000 ms  (56-356s)        – Scan for malware
  memory:     120,000 ms  (56-196s)        – Carve memory
  ───── Parallel phase complete ─────
  attack_map:   2,000 ms  (356-358s)       – Map to ATT&CK
  defense_map:  1,000 ms  (358-359s)       – Map to D3FEND
  report:      14,000 ms  (359-373s)       – Generate report
  
Total: ~373 seconds = 6 minutes 13 seconds

Parallelism:
  If run sequentially: 10 + 45 + 0.1 + 120 + 90 + 300 + 120 + 2 + 1 + 14 = 702 seconds (11.7 min)
  Actual (parallel):   373 seconds (6.2 min)
  Speedup: 1.9x (workers run simultaneously)
```

---

# WORKERSTATS TRACKING

## How Stats Are Built

```python
def agent_done(name: str, tokens_in: int, tokens_out: int):
    s = self.stats.setdefault(name, WorkerStats(name=name))
    s.input_tokens += tokens_in      # Accumulate LLM input tokens
    s.output_tokens += tokens_out    # Accumulate LLM output tokens
    s.finished_at = self._ts()       # Record finish time

def tool(agent: str, tool: str, exit_code: int|None, duration_ms: int|None):
    s = self.stats.setdefault(agent, WorkerStats(name=agent))
    s.tools_called += 1              # Count tool executions
    failed = exit_code is not None and exit_code != 0
    if failed:
        s.errors += 1                # Count failures
```

## Stats Summary Table

```
Worker          Input Tokens  Output Tokens  Tools  Errors  Cost
───────────────────────────────────────────────────────────────
filesystem      8,234         1,456          3      0       $0.0089
windows         6,789         1,234          2      0       $0.0074
malware_static  4,521         987            1      1       $0.0051
memory          3,456         654            1      0       $0.0039
attack_mapper   2,345         456            2      0       $0.0028
synthesizer     5,678         1,234          1      0       $0.0069
hasher          2,345         456            2      0       $0.0028
acquirer        1,234         234            1      0       $0.0016
defense_mapper  1,234         234            1      0       $0.0016
router          567           89             1      0       $0.0007
───────────────────────────────────────────────────────────────
TOTAL           37,381        8,252          15     1       $0.0397
```

---

# COST CALCULATION MODEL

## Haiku Pricing (Default Workers)

```
INPUT:  $1.00 per 1 million tokens
OUTPUT: $5.00 per 1 million tokens

Example - filesystem worker:
  Input tokens:  8,234
  Output tokens: 1,456
  
  Input cost:  (8,234 / 1,000,000) * $1.00 = $0.008234
  Output cost: (1,456 / 1,000,000) * $5.00 = $0.007280
  Total cost:  $0.015514

Scale analysis (full investigation):
  37,381 input tokens  * ($1 / 1M) = $0.037381
  8,252 output tokens  * ($5 / 1M) = $0.041260
  Total investigation: ~$0.079
```

## Opus Pricing (Optional Premium Agents)

```
INPUT:  $15.00 per 1 million tokens
OUTPUT: $75.00 per 1 million tokens

Example - if synthesizer used Opus instead:
  Input tokens:  5,678
  Output tokens: 1,234
  
  Input cost:  (5,678 / 1,000,000) * $15.00 = $0.085170
  Output cost: (1,234 / 1,000,000) * $75.00 = $0.092550
  Total cost:  $0.177720 (vs $0.0069 for Haiku)

Efficiency:
  Opus costs ~26x more than Haiku per token
  Used only when high-quality reasoning needed (supervisor, synthesizer)
  Most workers use cheap Haiku for speed + cost
```

## Real-Time Cost Tracking

```python
# During investigation:
for worker_name, stats in self.stats.items():
    in_rate = _OPUS_IN if worker_name in self.opus_agents else _HAIKU_IN
    out_rate = _OPUS_OUT if worker_name in self.opus_agents else _HAIKU_OUT
    
    cost = (stats.input_tokens / 1_000_000) * in_rate
    cost += (stats.output_tokens / 1_000_000) * out_rate
    
# Display in summary as "cost~$0.0365"
```

---

# INTEGRATION WITH LANGGRAPH

## How Logger Integrates with Graph Execution

```python
# From run.py

async def _drive(graph, args) -> None:
    log.case_start(args.case_id)  # Print header
    
    last_phase = ""
    async for chunk in graph.astream(initial, config):
        for node_name in chunk["data"].keys():
            # Detect phase transitions
            if node_name in _PHASE_NODES and node_name != last_phase:
                log.phase(node_name)  # Print phase change
                last_phase = node_name
    
    log.case_done(args.case_id)   # Print footer
    log.summary()                  # Print final stats

# Each worker node calls:
log.agent_start("filesystem", "walking 1 disk image(s)")
log.tool("filesystem", "fls", exit_code=0, duration_ms=2500)
log.agent_done("filesystem", tokens_in=8234, tokens_out=1456)
```

## Call Flow

```
run.py:_drive()
  ├─ log.case_start("RANSOMWARE-001")
  ├─ graph.astream() loops through phases:
  │   ├─ Phase: acquire
  │   │   └─ log.phase("acquire")
  │   ├─ Phase: hash
  │   │   └─ log.phase("hash")
  │   ├─ Phase: analyze
  │   │   └─ log.phase("analyze")
  │   │   └─ log.gate("gate_hash_ok", "ok")
  │   ├─ [PARALLEL WORKERS]
  │   │   ├─ filesystem worker
  │   │   │   ├─ log.agent_start("filesystem", "...")
  │   │   │   ├─ log.tool("filesystem", "fls", exit_code=0, ...)
  │   │   │   └─ log.agent_done("filesystem", tokens_in=8234, ...)
  │   │   ├─ windows worker
  │   │   ├─ malware_static worker
  │   │   ├─ memory worker
  │   │   └─ network worker
  │   ├─ Phase: attack_map
  │   │   └─ log.phase("attack_map")
  │   ├─ Phase: defense_map
  │   │   └─ log.phase("defense_map")
  │   ├─ Phase: report
  │   │   └─ log.phase("report")
  │   └─ Phase: done
  │
  ├─ log.case_done("RANSOMWARE-001")
  └─ log.summary()
     └─ Print table of stats + total cost
```

---

# DEBUGGING WITH AGENT LOGS

## Finding Performance Bottlenecks

```
=== SUMMARY ===
AGENT               IN        OUT    TOOLS  ERR
malware_static    4,521       987        1     1   ← Most tokens
filesystem        8,234     1,456        3     0   ← Most tools
windows           6,789     1,234        2     0
synthesizer       5,678     1,234        1     0
...

ACTION: 
  - malware_static: 300+ seconds (clamscan)
  - filesystem: 120+ seconds (fls recursive walk)
  These are I/O bound, parallelize them
```

## Detecting Tool Failures

```
[Tool]   malware_static      clamscan                   exit=1 duration=300000ms
[Error]  malware_static      Malware detection failed

=== SUMMARY ===
malware_static      ERR = 1   ← Tool failed

ACTION:
  - Check clamscan signatures (may be outdated)
  - Check evidence permissions (read access)
  - Review malware log in JSONL for details
```

## Estimating Cost Before Running

```
Assume:
  - Filesystem: 8,234 in tokens × 10 workers = 82,340 tokens
  - Windows: 6,789 in × 10 workers = 67,890 tokens
  - Malware: 4,521 in × 10 workers = 45,210 tokens
  - 5 specialist workers
  - Synthesizer (Opus): 5,678 in × 15 workers = 85,170 tokens
  
Total estimate: ~425,000 input tokens
  Haiku: (350K × $1 + 75K output × $5) / 1M = $0.53
  Opus: (85K × $15 + 17K output × $75) / 1M = $2.42
  
Budget check: $0.53 + $2.42 = ~$3.00 per investigation
```

## Monitoring Token Efficiency

```
Good efficiency:
  [Agent] filesystem       done   tokens in:8234 out:1456   ← 1:5.6 ratio
  [Agent] windows          done   tokens in:6789 out:1234   ← 1:5.5 ratio
  
Poor efficiency (too much output):
  [Agent] synthesizer      done   tokens in:5678 out:12000  ← 1:2.1 ratio
  
ACTION: Reduce output verbosity in system prompts
```

## Timeline Reconstruction

```
[00:45:34] [Phase]  filesystem   ← Started
[00:45:35] [Agent] filesystem     - walking disk image
[02:47:00] [Agent] filesystem     done              ← Finished
           Duration: 2:01 = 121 seconds

Parallel timeline:
  filesystem: 00:45:34 - 02:47:00 (121s)
  windows:    00:45:35 - 02:47:00 (122s)
  malware:    00:45:34 - 05:45:37 (300s)  ← Bottleneck!
  memory:     00:45:34 - 02:47:00 (122s)

Critical path: malware_static (300s) determines total time
ACTION: Parallelize malware scanning or use faster scanner
```

---

# COMPARISON: MCP LOGS vs AGENT LOGS

```
┌────────────────────┬──────────────────────┬──────────────────────┐
│ Aspect             │ MCP LOGS (JSONL)     │ AGENT LOGS (Console) │
├────────────────────┼──────────────────────┼──────────────────────┤
│ Purpose            │ Forensic audit trail │ Operational tracking │
│ Format             │ JSON (machine)       │ Text (human)         │
│ Audience           │ Judge, auditor       │ Operator, debugger   │
│ Timestamp          │ Microsecond (UTC)    │ Second precision     │
│ Tool details       │ Full command + output│ Tool name only       │
│ Immutable          │ Yes (append-only)    │ No (volatile)        │
│ Retention          │ Permanent            │ Session only         │
│ Admissible         │ Yes (court)          │ No                   │
│ Real-time          │ Appended every tool  │ Printed every event  │
│ Token cost         │ Not tracked          │ Tracked + calculated │
├────────────────────┼──────────────────────┼──────────────────────┤
│ Example:           │ {"tool": "clamscan", │ [10:30:45] [Tool]   │
│                    │  "exit_code": 1,    │ malware    clamscan  │
│                    │  "stdout": "...     │ exit=1 duration=...  │
│                    │  FOUND",            │                      │
│                    │  "timestamp": "..."}│                      │
└────────────────────┴──────────────────────┴──────────────────────┘

USAGE:
  Post-investigation: Read JSONL logs for audit
  During investigation: Watch console output for progress
  Cost estimation: Check agent summary at end
  Debugging: Use both (console shows overview, JSONL shows details)
```

---

# EXAMPLE: READING AGENT LOGS DURING INVESTIGATION

## Investigator's View (Real-Time)

```bash
$ python run.py --case-id RANSOMWARE-001 --evidence /evidence/disk.E01

=== CASE RANSOMWARE-001 ===
[00:00:01] [Phase]  acquire
[00:00:02] [Agent] acquirer            - analyzing evidence format
[00:00:05] [Agent] acquirer            done   tokens in:1234 out:234

[00:00:06] [Phase]  hash
[00:00:07] [Agent] hasher              - hashing evidence
[00:45:30] [Agent] hasher              done   tokens in:2345 out:456

[00:45:31] [Phase]  analyze
[00:45:32] [Gate]   gate_hash_ok        -> ok

[00:45:33] [Phase]  filesystem
[00:45:34] [Phase]  windows
[00:45:35] [Phase]  malware
[00:45:36] [Phase]  memory
[00:45:37] [Phase]  network
[00:45:38] [Agent] filesystem          - walking disk image
[00:45:39] [Agent] windows             - analyzing artifacts
[00:45:40] [Agent] malware_static      - scanning signatures
[00:45:41] [Agent] memory              - extracting dump
[00:45:42] [Agent] network             - analyzing traffic
...
[02:47:00] [Agent] filesystem          done   tokens in:8234 out:1456
[02:47:00] [Agent] windows             done   tokens in:6789 out:1234
[02:47:00] [Agent] memory              done   tokens in:3456 out:654
[02:47:00] [Agent] network             done   tokens in:2345 out:456
[05:45:37] [Agent] malware_static      done   tokens in:4521 out:987
...
=== CASE RANSOMWARE-001 COMPLETE ===

=== SUMMARY ===
AGENT               IN        OUT     TOOLS   ERR
filesystem         8234      1456        3     0
windows            6789      1234        2     0
malware_static     4521       987        1     1
memory             3456       654        1     0
network            2345       456        1     0
attack_mapper      2345       456        2     0
synthesizer        5678      1234        1     0
hasher             2345       456        2     0
acquirer           1234       234        1     0
defense_mapper     1234       234        1     0
router              567        89        1     0
TOTAL             37381      8252       15     1   cost~$0.0365
```

## What Operator Observes

1. **First 10 seconds**: Acquisition + hashing (foundation)
2. **10-50 seconds**: All 5 workers launch simultaneously
3. **50-300 seconds**: Wait for malware scanning (bottleneck)
4. **300-360 seconds**: Attack/defense mapping (quick)
5. **360-375 seconds**: Report generation
6. **Final**: See cost estimate ($0.04 per investigation)

## What Investigator Learns from Summary

```
✅ Findings collected by worker:
   filesystem: 3 tools called (MFT walk, file listing, carving)
   windows: 2 tools (registry, events)
   malware: 1 tool, 1 error (clamscan found malware)
   
❌ One error in malware detection (but didn't stop investigation)

💰 Cost: $0.0365 (very cheap!)

⏱️  Timing: 6+ minutes total (parallel workers = fast)
   - If sequential: would be 11+ minutes
   - Parallelism saved ~5 minutes!
```

---

# SUMMARY: AI AGENT LOGS

```
AI Agent Logs = Real-time investigation dashboard

What they show:
  ✓ When each phase starts/ends
  ✓ Which workers are active
  ✓ How many tools each worker calls
  ✓ Success/failure of tools
  ✓ LLM token usage per worker
  ✓ Real-time cost calculation
  ✓ Gate decisions (continue/halt)
  ✓ Error messages
  ✓ Final statistics and total cost

Benefits:
  • Color-coded for quick scanning
  • Thread-safe output (parallel workers)
  • Cost transparency
  • Timing visibility
  • Error detection
  • Operator confirmation

Integration:
  • Called by each worker node in LangGraph
  • Happens in real-time as investigation runs
  • Culminates in summary() at end
  • Provides audit trail for operator
```

