# Building a TUI for SIFT-MCP - Complete Guide

**TUI = Text User Interface** (interactive terminal dashboard, not just logs)

---

# TABLE OF CONTENTS
1. [Why TUI is Needed](#why-tui-is-needed)
2. [TUI Architecture](#tui-architecture)
3. [Layout Design](#layout-design)
4. [Real-Time Update System](#real-time-update-system)
5. [Implementation Stack](#implementation-stack)
6. [Code Examples](#code-examples)
7. [Interactive Features](#interactive-features)
8. [Full Mockup & Flow](#full-mockup--flow)

---

# WHY TUI IS NEEDED

## Current Limitations (Console Logger)

```
Current:
├─ Scrolling text output
├─ Hard to track multiple workers simultaneously
├─ Must read entire log to understand state
├─ No way to drill down into details
├─ Cost appears only at end
└─ Can't interact or pause/resume

Needed:
├─ Real-time worker status dashboard
├─ At-a-glance worker metrics
├─ Click to drill down into tool details
├─ Live cost tracking
├─ Ability to pause/cancel/filter findings
└─ Search & filter capabilities
```

## Benefits of TUI

```
✅ Visibility: See all workers at once, not scrolling
✅ Responsiveness: Update metrics in real-time (no refresh)
✅ Interactivity: Pause, cancel, drill down
✅ Cost Control: Watch budget in real-time, stop if needed
✅ Debugging: Click on error to see JSONL entry
✅ Professional: Looks like commercial IR tools
```

---

# TUI ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────┐
│                      SIFT-MCP TUI                           │
├─────────────────────────────────────────────────────────────┤
│
│  Layers (MVC pattern):
│
│  ┌─────────────────────────────────────────────────────────┐
│  │  PRESENTATION LAYER (Terminal UI)                       │
│  │  ├─ Rich/Textual widgets                                │
│  │  ├─ Layout manager (4-5 panels)                         │
│  │  ├─ Event loop (keyboard, mouse)                        │
│  │  └─ Real-time rendering                                 │
│  └─────────────────────────────────────────────────────────┘
│           ▲
│           │ Async updates
│           │
│  ┌─────────────────────────────────────────────────────────┐
│  │  STATE LAYER (Data Management)                          │
│  │  ├─ Case state (LangGraph state)                        │
│  │  ├─ Worker metrics (WorkerStats)                        │
│  │  ├─ Tool execution log (in-memory)                      │
│  │  ├─ Findings (as they arrive)                           │
│  │  └─ Selected item (for drill-down)                      │
│  └─────────────────────────────────────────────────────────┘
│           ▲
│           │ WebSocket/Queue
│           │
│  ┌─────────────────────────────────────────────────────────┐
│  │  DATA LAYER (LangGraph Agent)                           │
│  │  ├─ graph.astream() loop                                │
│  │  ├─ Worker nodes executing                              │
│  │  ├─ Tool calls happening                                │
│  │  └─ Publish metrics to TUI via queue                    │
│  └─────────────────────────────────────────────────────────┘
```

## Communication Flow

```
LangGraph Worker Node
  ├─ Call tool
  ├─ Get result
  └─ PUT to Queue: {"worker": "filesystem", "tool": "fls", "exit_code": 0, "duration_ms": 2500}
       ▼
TUI Event Loop (async)
  ├─ Receive from queue
  ├─ Update WorkerStats
  └─ Render new frame
       ▼
User sees:
  "filesystem: 3 tools, 2500ms"
```

---

# LAYOUT DESIGN

## Full Screen Mock-Up (80x30 terminal)

```
╔════════════════════════════════════════════════════════════════════════════╗
║  SIFT-MCP Investigation Dashboard                                          ║
║  Case: RANSOMWARE-001 | Started: 10:00:15 | Elapsed: 05:42 | Status: ▶ Running
╠════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  WORKERS (5 Active)                    │  FINDINGS (12)                     ║
║  ╭──────────────────────────────────╮  │  ╭──────────────────────────────╮  ║
║  │ filesystem          ████████░░░░░ │  │  │ 1. Ransomware.LockBit.A     │  ║
║  │ tokens: 8234↓ 1456↑ 3 tools, 0✗  │  │  │ 2. Registry Run Key: persistence
║  │                                   │  │  │ 3. Event ID 4688: PowerShell
║  │ windows             ██████░░░░░░░ │  │  │ 4. Unsigned executable
║  │ tokens: 6789↓ 1234↑ 2 tools, 0✗  │  │  │ 5. Recently modified binary
║  │                                   │  │  │ 6. ATT&CK: T1547.001
║  │ malware_static      ███████████░░ │  │  │ 7. ATT&CK: T1059.001
║  │ tokens: 4521↓ 987↑  1 tools, 1✗   │  │  │ 8. Threat: APT29 (87%)
║  │                                   │  │  │ 9. YARA: Emotet downloader
║  │ memory              ██████░░░░░░░ │  │  │ 10. Suspicious registry key
║  │ tokens: 3456↓ 654↑  1 tools, 0✗   │  │  │ ...
║  │                                   │  │  │                              │
║  │ network             ██░░░░░░░░░░░ │  │  │ [↑↓ scroll]  [c] copy [d] del│
║  │ tokens: 2345↓ 456↑  1 tools, 0✗   │  │  │                              │
║  │                                   │  │  │ Total findings: 12           │
║  │ ░ = allocating  █ = running       │  │  │ Confidence: 87%              │
║  │ [q] quick stats [d] drill [p] pause│  │  │ Cost so far: $0.024          │
║  │                                   │  │  ╰──────────────────────────────╯  ║
║  ╰──────────────────────────────────╯  │                                    ║
║                                        │                                    ║
║  TIMELINE                              │  ACTIVE TOOL                       ║
║  ╭──────────────────────────────────╮  │  ╭──────────────────────────────╮  ║
║  │ 10:00:15 - Phase: acquire        │  │  │ Worker: filesystem           │  ║
║  │ 10:00:20 - Phase: hash           │  │  │ Tool: fls                    │  ║
║  │ 10:00:25 - Gate: hash_ok ✓       │  │  │ Command: /usr/bin/fls -r ... │  ║
║  │ 10:00:30 - Workers launched (5)  │  │  │ Duration: 124.5s             │  ║
║  │ 10:02:15 - filesystem complete   │  │  │ Output: 450,000 files        │  ║
║  │ 10:02:16 - windows complete      │  │  │ Status: ▶ Running...         │  ║
║  │ 10:04:45 - malware complete      │  │  │                              │  ║
║  │ 10:02:16 - memory complete       │  │  │ Press 's' to stop, 'j' for  │  ║
║  │ [scroll]                         │  │  │ JSONL entry                  │  ║
║  ╰──────────────────────────────────╯  │  │                              │  ║
║                                        │  ╰──────────────────────────────╯  ║
╠════════════════════════════════════════════════════════════════════════════╣
║ Cost: $0.0246 | Tokens: 37,381 in ↓ 8,252 out ↑ | Phase: malware | [h] help║
╚════════════════════════════════════════════════════════════════════════════╝
```

## Panel Breakdown

### Panel 1: Workers Status (Left, 30 chars wide)

```
filesystem          ████████░░░░░
tokens: 8234↓ 1456↑ 3 tools, 0✗

Elements:
  ├─ Agent name (truncated to 16 chars)
  ├─ Progress bar (13 chars) showing: active, waiting, complete
  ├─ Token counts (input↓, output↑)
  ├─ Tools called
  └─ Error count (✗ = red if > 0)

Color:
  ├─ GREEN = running
  ├─ YELLOW = waiting
  ├─ CYAN = complete
  └─ RED = errors
```

### Panel 2: Findings List (Right, 30 chars wide)

```
1. Ransomware.LockBit.A
2. Registry Run Key
3. Event ID 4688
...

Elements:
  ├─ Numbered list of findings
  ├─ Truncated description (28 chars max)
  ├─ Scroll controls (↑↓)
  ├─ Copy/Delete controls
  └─ Total count + confidence

Color:
  ├─ RED = high confidence finding
  ├─ YELLOW = medium confidence
  └─ DIM = low confidence
```

### Panel 3: Timeline (Bottom-left, 40 chars wide)

```
10:00:15 - Phase: acquire
10:00:20 - Phase: hash
10:02:15 - filesystem complete

Elements:
  ├─ Timestamp
  ├─ Event type
  ├─ Scrollable history
  └─ Click to drill down

Colors:
  ├─ CYAN = major events
  ├─ GREEN = success
  └─ RED = errors
```

### Panel 4: Active Tool Details (Bottom-right, 40 chars wide)

```
Worker: filesystem
Tool: fls
Command: /usr/bin/fls -r /evidence
Duration: 124.5s
Output: 450,000 files
Status: ▶ Running...

Elements:
  ├─ Current tool name
  ├─ Full command
  ├─ Real-time duration counter
  ├─ First 500 chars of output
  ├─ Live status
  └─ Action buttons (stop, view JSONL)
```

### Panel 5: Status Bar (Bottom)

```
Cost: $0.0246 | Tokens: 37,381 in ↓ 8,252 out ↑ | Phase: malware | [h] help

Elements:
  ├─ Real-time cost estimate
  ├─ Total tokens so far
  ├─ Current phase
  ├─ Keyboard shortcuts
  └─ Help indicator
```

---

# REAL-TIME UPDATE SYSTEM

## Data Flow Architecture

```python
# In LangGraph worker node:

async def filesystem_worker(state):
    # Before tool call
    tui_queue.put({
        "type": "agent_start",
        "name": "filesystem",
        "doing": "walking disk image"
    })
    
    # Tool execution
    result = await tool_call("fls", "-r", "/evidence")
    
    # After tool call
    tui_queue.put({
        "type": "tool_done",
        "agent": "filesystem",
        "tool": "fls",
        "exit_code": result.exit_code,
        "duration_ms": result.duration_ms,
        "output": result.stdout[:500]  # First 500 chars
    })
    
    # When done
    tui_queue.put({
        "type": "agent_done",
        "agent": "filesystem",
        "tokens_in": 8234,
        "tokens_out": 1456
    })
```

## TUI Event Loop

```python
# In TUI main thread:

async def tui_event_loop(screen):
    while True:
        # Check for queue updates
        while not tui_queue.empty():
            msg = tui_queue.get()
            
            if msg["type"] == "agent_start":
                state.workers[msg["name"]] = {
                    "status": "running",
                    "started": time.time()
                }
            
            elif msg["type"] == "tool_done":
                state.tools_executed.append(msg)
                state.workers[msg["agent"]]["last_tool"] = msg
            
            elif msg["type"] == "agent_done":
                state.workers[msg["agent"]]["status"] = "complete"
                state.workers[msg["agent"]]["tokens_in"] = msg["tokens_in"]
                state.workers[msg["agent"]]["tokens_out"] = msg["tokens_out"]
            
            elif msg["type"] == "finding":
                state.findings.append(msg)
        
        # Render all panels
        render_workers_panel(screen, state.workers)
        render_findings_panel(screen, state.findings)
        render_timeline_panel(screen, state.timeline)
        render_active_tool_panel(screen, state.current_tool)
        render_status_bar(screen, state)
        
        # Handle keyboard input
        key = await screen.get_key(timeout=100ms)
        if key == 'q': exit()
        elif key == 'd': drill_down_selected()
        elif key == 'p': pause_investigation()
        
        # Update elapsed time
        state.elapsed = time.time() - state.started
        
        # Sleep for 100ms then refresh
        await asyncio.sleep(0.1)
```

---

# IMPLEMENTATION STACK

## Python Libraries Needed

```
┌────────────────────────────────────────────────────────────┐
│  TUI Framework                                              │
├────────────────────────────────────────────────────────────┤
│  Option 1: Textual (Rich creator, most powerful)           │
│    - Full widget library (tables, trees, buttons)          │
│    - Mouse support, CSS styling                            │
│    - Async-first design                                    │
│    - Best for: Professional dashboards                     │
│                                                             │
│  Option 2: Blessed (simpler, lighter)                      │
│    - Lower-level cursor/color control                      │
│    - Good for: Real-time monitoring                        │
│    - Less overhead                                         │
│                                                             │
│  Option 3: Curses + Rich (hybrid)                          │
│    - Curses for layout, Rich for formatting                │
│    - Good for: Custom control + pretty output             │
└────────────────────────────────────────────────────────────┘

RECOMMENDED: Textual (most complete)

Installation:
  pip install textual rich asyncio

Additional:
  pip install pydantic  # For state management
```

## Architecture Pattern

```
sift-tui/
├── main.py                 # Entry point
├── app.py                  # Textual App class
├── state.py               # State management (WorkerStats, Findings)
├── widgets/
│   ├── workers_panel.py   # Worker status display
│   ├── findings_panel.py  # Findings list
│   ├── timeline_panel.py  # Timeline
│   ├── tool_detail_panel.py # Active tool details
│   └── status_bar.py      # Bottom status
├── models/
│   ├── worker.py          # WorkerStats extended
│   ├── finding.py         # Finding model
│   └── event.py           # TUI event types
├── queue_handler.py       # LangGraph → TUI communication
└── styles.css             # Textual styling
```

---

# CODE EXAMPLES

## 1. Textual App Skeleton

```python
# app.py
from textual.app import ComposeResult, on, work
from textual.containers import Container, Vertical, Horizontal
from textual.widgets import Header, Footer, Static, Label
import asyncio
from queue import Queue

from widgets.workers_panel import WorkersPanel
from widgets.findings_panel import FindingsPanel
from widgets.timeline_panel import TimelinePanel
from widgets.tool_detail_panel import ToolDetailPanel
from state import TUIState

class SiftMCPDashboard(ComposeResult):
    """Main TUI application."""
    
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("d", "drill_down", "Drill Down"),
        ("p", "pause", "Pause"),
        ("r", "resume", "Resume"),
        ("h", "help", "Help"),
    ]
    
    CSS = """
    Screen {
        background: $panel;
    }
    
    #workers-panel {
        width: 40%;
        border: solid green;
    }
    
    #findings-panel {
        width: 60%;
        border: solid cyan;
    }
    
    #timeline-panel {
        height: 40%;
        border: solid yellow;
    }
    
    #active-tool-panel {
        height: 40%;
        border: solid magenta;
    }
    """
    
    def __init__(self, case_id: str, evidence_paths: list[str]):
        super().__init__()
        self.case_id = case_id
        self.evidence_paths = evidence_paths
        self.state = TUIState(case_id)
        self.tui_queue = Queue()
    
    def compose(self) -> ComposeResult:
        """Compose the layout."""
        yield Header()
        
        with Vertical():
            # Top row: workers + findings
            with Horizontal():
                yield WorkersPanel(id="workers-panel", state=self.state)
                yield FindingsPanel(id="findings-panel", state=self.state)
            
            # Bottom row: timeline + active tool
            with Horizontal():
                yield TimelinePanel(id="timeline-panel", state=self.state)
                yield ToolDetailPanel(id="active-tool-panel", state=self.state)
            
            # Status bar
            yield StatusBar(id="status-bar", state=self.state)
        
        yield Footer()
    
    @work
    async def start_investigation(self):
        """Start the investigation."""
        from graph import build_graph
        
        graph = build_graph()
        config = {
            "configurable": {"thread_id": f"case-{self.case_id}"},
            "recursion_limit": 200,
        }
        
        initial = {
            "case_id": self.case_id,
            "evidence": [{"path": p, "chain_of_custody": []} for p in self.evidence_paths],
            "findings": [],
            "errors": [],
            "candidate_files": [],
        }
        
        # Run graph while reading updates from queue
        async for chunk in graph.astream(initial, config, stream_mode=["updates"]):
            # Process updates and put to queue for TUI
            self._process_chunk(chunk)
            
            # Update TUI (non-blocking)
            await self._update_panels()
            await asyncio.sleep(0.05)
    
    def _process_chunk(self, chunk):
        """Extract metrics from LangGraph chunk and put to queue."""
        if chunk["type"] != "updates":
            return
        
        for node_name, node_output in chunk["data"].items():
            if "metrics" in node_output:
                self.tui_queue.put({
                    "type": "metrics",
                    "agent": node_name,
                    "metrics": node_output["metrics"]
                })
    
    async def _update_panels(self):
        """Update all panels from queue."""
        while not self.tui_queue.empty():
            msg = self.tui_queue.get()
            
            if msg["type"] == "metrics":
                self.state.update_worker(msg["agent"], msg["metrics"])
                
                # Update specific widgets
                workers_panel = self.query_one("#workers-panel", WorkersPanel)
                workers_panel.update(self.state)
    
    def action_drill_down(self):
        """Drill down into selected finding."""
        findings_panel = self.query_one("#findings-panel", FindingsPanel)
        finding = findings_panel.selected_finding
        if finding:
            self.notify(f"Drilling into: {finding['claim']}")
    
    def action_pause(self):
        """Pause investigation."""
        self.state.paused = True
        self.notify("Investigation paused")
    
    def action_resume(self):
        """Resume investigation."""
        self.state.paused = False
        self.notify("Investigation resumed")

if __name__ == "__main__":
    import sys
    case_id = sys.argv[1] if len(sys.argv) > 1 else "TEST-001"
    evidence = sys.argv[2:] if len(sys.argv) > 2 else ["/evidence/disk.img"]
    
    app = SiftMCPDashboard(case_id, evidence)
    app.run()
```

## 2. Workers Panel Widget

```python
# widgets/workers_panel.py
from textual.widgets import Static
from textual.containers import Container
from rich.table import Table
from rich.progress import Progress, BarColumn
from state import TUIState

class WorkersPanel(Static):
    """Display worker status."""
    
    def __init__(self, state: TUIState, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.state = state
    
    def render(self) -> str:
        """Render workers status."""
        table = Table(title="Workers Status", show_header=False)
        
        for name, worker in self.state.workers.items():
            # Progress bar
            progress = Progress(
                BarColumn(bar_width=13),
                transient=True
            )
            
            task_id = progress.add_task(
                "", 
                completed=worker["progress"]
            )
            
            # Format: name | progress | tokens | tools
            row = [
                f"{name:<16}",
                f"{'█' * int(worker['progress'] / 8)}{'░' * (13 - int(worker['progress'] / 8))}",
                f"in:{worker['tokens_in']:<5} out:{worker['tokens_out']:<5}",
                f"{worker['tools_called']:<3} tools",
            ]
            
            # Color based on status
            if worker["status"] == "running":
                color = "green"
            elif worker["status"] == "complete":
                color = "cyan"
            else:
                color = "dim"
            
            for cell in row:
                table.add_row(cell, style=color)
        
        return self.render_str(table)
```

## 3. State Management

```python
# state.py
from dataclasses import dataclass, field
from typing import Dict, List
import time

@dataclass
class WorkerState:
    name: str
    status: str = "idle"  # idle, running, complete
    progress: int = 0  # 0-100
    tools_called: int = 0
    errors: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    started_at: float = 0.0
    finished_at: float = 0.0
    last_tool: str = ""
    duration_sec: float = 0.0

@dataclass
class TUIState:
    case_id: str
    workers: Dict[str, WorkerState] = field(default_factory=dict)
    findings: List[Dict] = field(default_factory=list)
    timeline: List[Dict] = field(default_factory=list)
    current_tool: Dict = field(default_factory=dict)
    
    started_at: float = field(default_factory=time.time)
    paused: bool = False
    total_cost: float = 0.0
    
    def update_worker(self, name: str, metrics: Dict):
        """Update worker stats from metrics."""
        if name not in self.workers:
            self.workers[name] = WorkerState(name=name)
        
        worker = self.workers[name]
        
        if "status" in metrics:
            worker.status = metrics["status"]
        
        if "tokens_in" in metrics:
            worker.tokens_in = metrics["tokens_in"]
        
        if "tokens_out" in metrics:
            worker.tokens_out = metrics["tokens_out"]
        
        # Calculate progress (0-100)
        if worker.status == "running":
            worker.progress = 50 + (worker.tools_called % 5) * 10
        elif worker.status == "complete":
            worker.progress = 100
        
        # Update cost
        self.total_cost = self._calculate_cost()
    
    def _calculate_cost(self) -> float:
        """Calculate total cost so far."""
        cost = 0.0
        for worker in self.workers.values():
            cost += (worker.tokens_in / 1_000_000) * 1.0  # Haiku input
            cost += (worker.tokens_out / 1_000_000) * 5.0  # Haiku output
        return cost
    
    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self.started_at
    
    @property
    def elapsed_formatted(self) -> str:
        total_seconds = int(self.elapsed_seconds)
        minutes = total_seconds // 60
        seconds = total_seconds % 60
        return f"{minutes:02d}:{seconds:02d}"
```

---

# INTERACTIVE FEATURES

## Keyboard Controls

```
┌─────────────┬──────────────────────────────────────────┐
│ Key         │ Action                                   │
├─────────────┼──────────────────────────────────────────┤
│ q           │ Quit investigation (confirm)             │
│ p           │ Pause investigation (can resume)         │
│ r           │ Resume investigation                     │
│ d           │ Drill down into selected finding         │
│ j           │ Jump to JSONL entry for tool             │
│ c           │ Copy finding to clipboard                │
│ /           │ Search findings                          │
│ ↑ ↓ ← →     │ Navigate panels                          │
│ Tab         │ Switch focus between panels              │
│ Enter       │ Select/expand item                       │
│ Esc         │ Close drill-down view                    │
│ h           │ Show help                                │
│ e           │ Export case as JSON                      │
└─────────────┴──────────────────────────────────────────┘
```

## Mouse Support

```
Click Actions:
  ├─ Worker card → Show worker details
  ├─ Finding → Drill down into details
  ├─ Timeline event → Jump to that tool's JSONL
  ├─ Tool details → Copy command to clipboard
  └─ Status bar → Show full stats modal

Scroll:
  ├─ Findings panel → Scroll findings list
  ├─ Timeline → Scroll timeline events
  └─ Tool output → Scroll output text
```

## Modal Dialogs

```
┌────────────────────────────────────────────────────┐
│ Quick Stats (press 'q' while viewing worker)       │
├────────────────────────────────────────────────────┤
│                                                    │
│  Worker: filesystem                                │
│  Status: complete                                  │
│  Duration: 2m 14s                                  │
│  Tools called: 3                                   │
│  Errors: 0                                         │
│  Tokens in: 8,234                                  │
│  Tokens out: 1,456                                 │
│  Cost: $0.0141                                     │
│  Efficiency: 5.66 tokens out / tokens in          │
│                                                    │
│  [Close]                                           │
└────────────────────────────────────────────────────┘

Drill-Down Finding (press 'd' on finding):
┌────────────────────────────────────────────────────┐
│ RANSOMWARE.LOCKBIT.A                               │
├────────────────────────────────────────────────────┤
│                                                    │
│ Detection:                                         │
│   Tool: clamscan                                   │
│   Found: /evidence/files/svc_manager.exe           │
│   Signature: Ransomware.LockBit.A FOUND            │
│   Confidence: 99%                                  │
│                                                    │
│ Context:                                           │
│   Found in: Windows System32 directory             │
│   Size: 245,632 bytes                              │
│   Modified: 2026-05-15 14:32:15 UTC               │
│   Hash: SHA256: abc123...                          │
│                                                    │
│ Related Findings:                                  │
│   - Registry: Run key points to same file          │
│   - ATT&CK: T1547.001 (Registry persistence)      │
│   - Threat Actor: LockBit (87% confidence)        │
│                                                    │
│ Actions:                                           │
│   [View in JSONL]  [Export]  [Next Finding]       │
│                                                    │
│                             [Close]               │
└────────────────────────────────────────────────────┘
```

---

# FULL MOCKUP & FLOW

## Timeline: Investigation Start to Completion

### T=0s: Initial Screen

```
╔════════════════════════════════════════════════════════════════╗
║  SIFT-MCP Investigation Dashboard                              ║
║  Case: RANSOMWARE-001 | Started: 14:00:00 | Elapsed: 00:00 | ▶
╠════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  WORKERS (0/5 Active)          │  FINDINGS (0)                  ║
║  ╭──────────────────────────╮  │  ╭──────────────────────────╮  ║
║  │ (waiting to start...)    │  │  │ (no findings yet)        │  ║
║  │                          │  │  │                          │  ║
║  │                          │  │  │                          │  ║
║  ╰──────────────────────────╯  │  ╰──────────────────────────╯  ║
║                                │                                ║
║  TIMELINE                      │  ACTIVE TOOL                   ║
║  ╭──────────────────────────╮  │  ╭──────────────────────────╮  ║
║  │ Waiting for start...     │  │  │ Waiting for tool...      │  ║
║  ╰──────────────────────────╯  │  ╰──────────────────────────╯  ║
║                                │                                ║
╠════════════════════════════════════════════════════════════════╣
║ Cost: $0.0000 | Tokens: 0 in ↓ 0 out ↑ | Status: Ready | [h] help
╚════════════════════════════════════════════════════════════════╝
```

### T=10s: Acquisition & Hashing Phase

```
╔════════════════════════════════════════════════════════════════╗
║  SIFT-MCP Investigation Dashboard                              ║
║  Case: RANSOMWARE-001 | Started: 14:00:00 | Elapsed: 00:10 | ▶
╠════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  WORKERS (1 Active)            │  FINDINGS (0)                  ║
║  ╭──────────────────────────╮  │  ╭──────────────────────────╮  ║
║  │ hasher      ███░░░░░░░░░ │  │  │ (analyzing...)           │  ║
║  │ in:2345 out:456          │  │  │                          │  ║
║  │ 2 tools, 0✗              │  │  │                          │  ║
║  ╰──────────────────────────╯  │  ╰──────────────────────────╯  ║
║                                │                                ║
║  TIMELINE                      │  ACTIVE TOOL                   ║
║  ╭──────────────────────────╮  │  ╭──────────────────────────╮  ║
║  │ 14:00:00 Phase: acquire  │  │  │ Worker: hasher           │  ║
║  │ 14:00:05 ewfinfo [done]  │  │  │ Tool: sha256deep         │  ║
║  │ 14:00:10 sha256deep [⟳]  │  │  │ Duration: 8.5s           │  ║
║  ╰──────────────────────────╯  │  │ Output: Computing...     │  ║
║                                │  ╰──────────────────────────╯  ║
║                                │                                ║
╠════════════════════════════════════════════════════════════════╣
║ Cost: $0.0031 | Tokens: 2345 in ↓ 456 out ↑ | Phase: hash | [h] help
╚════════════════════════════════════════════════════════════════╝
```

### T=60s: All Workers Launched (Parallel Phase)

```
╔════════════════════════════════════════════════════════════════╗
║  SIFT-MCP Investigation Dashboard                              ║
║  Case: RANSOMWARE-001 | Started: 14:00:00 | Elapsed: 01:00 | ▶
╠════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  WORKERS (5 Active)            │  FINDINGS (3)                  ║
║  ╭──────────────────────────╮  │  ╭──────────────────────────╮  ║
║  │ filesystem ██████░░░░░░░ │  │  │ 1. Unsigned executable   │  ║
║  │ in:3456 out:789          │  │  │ 2. Registry Run key      │  ║
║  │ 1/3 tools, 0✗            │  │  │ 3. Event ID 4688         │  ║
║  │                          │  │  │                          │  ║
║  │ windows    ████░░░░░░░░░ │  │  │ Confidence: 76%          │  ║
║  │ in:2345 out:567          │  │  │ Cost est: $0.018         │  ║
║  │ 1/2 tools, 0✗            │  │  ╰──────────────────────────╯  ║
║  │                          │  │                                ║
║  │ malware    █░░░░░░░░░░░░ │  │                                ║
║  │ in:1234 out:234          │  │                                ║
║  │ 0/1 tools, 0✗            │  │                                ║
║  │                          │  │                                ║
║  │ memory     ██░░░░░░░░░░░ │  │                                ║
║  │ in:890 out:156           │  │                                ║
║  │ 0/1 tools, 0✗            │  │                                ║
║  │                          │  │                                ║
║  │ network    ░░░░░░░░░░░░░ │  │                                ║
║  │ in:0 out:0               │  │                                ║
║  │ 0/1 tools, 0✗            │  │                                ║
║  ╰──────────────────────────╯  │                                ║
║                                │                                ║
║  TIMELINE                      │  ACTIVE TOOL                   ║
║  ╭──────────────────────────╮  │  ╭──────────────────────────╮  ║
║  │ 14:00:45 Workers launched │  │  │ Worker: malware_static   │  ║
║  │ 14:00:48 filesystem start │  │  │ Tool: clamscan           │  ║
║  │ 14:00:50 windows start    │  │  │ Duration: 45.2s          │  ║
║  │ 14:00:51 malware start    │  │  │ Output: [████...░░░░]   │  ║
║  ╰──────────────────────────╯  │  │ Scanning: 450,234/500k   │  ║
║                                │  ╰──────────────────────────╯  ║
║                                │                                ║
╠════════════════════════════════════════════════════════════════╣
║ Cost: $0.0142 | Tokens: 18,234 in ↓ 3,456 out ↑ | Phase: malware | [p] pause
╚════════════════════════════════════════════════════════════════╝
```

### T=350s: Bottleneck (Malware Scanning Still Running)

```
╔════════════════════════════════════════════════════════════════╗
║  SIFT-MCP Investigation Dashboard                              ║
║  Case: RANSOMWARE-001 | Started: 14:00:00 | Elapsed: 05:50 | ▶
╠════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  WORKERS (1 Active)            │  FINDINGS (12)                 ║
║  ╭──────────────────────────╮  │  ╭──────────────────────────╮  ║
║  │ filesystem ████████████  │  │  │ 1. Ransomware.LockBit.A  │  ║
║  │ in:8234 out:1456 [done]  │  │  │ 2. Registry Persistence  │  ║
║  │ 3 tools, 0✗              │  │  │ 3. Suspicious .exe       │  ║
║  │                          │  │  │ 4. Event ID 4688 x3      │  ║
║  │ windows    ████████████  │  │  │ 5. ATT&CK: T1047        │  ║
║  │ in:6789 out:1234 [done]  │  │  │ 6. ATT&CK: T1059.001     │  ║
║  │ 2 tools, 0✗              │  │  │ 7. Threat: APT29         │  ║
║  │                          │  │  │ 8. YARA: Emotet          │  ║
║  │ malware    ███████████░░ │  │  │ 9. ADS Stream            │  ║
║  │ in:4521 out:987 [95% 🟢] │  │  │ 10. Deleted MFT entry    │  ║
║  │ 1 tool, 0✗               │  │  │ 11. Modified kernel obj  │  ║
║  │                          │  │  │ 12. Registry HexEdit      │  ║
║  │ memory     ████████████  │  │  │                          │  ║
║  │ in:3456 out:654 [done]   │  │  │ Confidence: 94%          │  ║
║  │ 1 tool, 0✗               │  │  │ Cost: $0.037             │  ║
║  │                          │  │  ╰──────────────────────────╯  ║
║  │ network    ████████████  │  │                                ║
║  │ in:2345 out:456 [done]   │  │                                ║
║  │ 1 tool, 0✗               │  │                                ║
║  ╰──────────────────────────╯  │                                ║
║                                │                                ║
║  TIMELINE                      │  ACTIVE TOOL                   ║
║  ╭──────────────────────────╮  │  ╭──────────────────────────╮  ║
║  │ 14:02:15 filesystem done  │  │  │ Worker: malware_static   │  ║
║  │ 14:02:16 windows done     │  │  │ Tool: clamscan           │  ║
║  │ 14:02:17 memory done      │  │  │ Duration: 299.7s         │  ║
║  │ 14:02:18 network done     │  │  │ Output: 12 INFECTED      │  ║
║  │ 14:05:50 malware [⟳]95%   │  │  │ Files:                   │  ║
║  ├──────────────────────────┤  │  │  - svc_manager.exe       │  ║
║  │ Critical path: malware    │  │  │  - payload.dll           │  ║
║  │ ETA: 1m 5s                │  │  │  - (10 more...)          │  ║
║  ╰──────────────────────────╯  │  ╰──────────────────────────╯  ║
║                                │                                ║
╠════════════════════════════════════════════════════════════════╣
║ Cost: $0.0237 | Tokens: 27,345 in ↓ 5,187 out ↑ | Phase: malware | [p] pause
╚════════════════════════════════════════════════════════════════╝
```

### T=375s: Complete & Report

```
╔════════════════════════════════════════════════════════════════╗
║  SIFT-MCP Investigation Dashboard                              ║
║  Case: RANSOMWARE-001 | Started: 14:00:00 | Elapsed: 06:15 | ✓
╠════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  WORKERS (0 Active) [COMPLETE]  │  FINDINGS (12) FINALIZED      ║
║  ╭──────────────────────────╮  │  ╭──────────────────────────╮  ║
║  │ filesystem ████████████  │  │  │ 1. Ransomware.LockBit.A  │  ║
║  │ in:8234 out:1456 [done]  │  │  │    Confidence: 99%       │  ║
║  │ 3 tools, 0✗ (0.89s)       │  │  │                          │  ║
║  │                          │  │  │ 2. Threat: APT29         │  ║
║  │ windows    ████████████  │  │  │    Confidence: 87%       │  ║
║  │ in:6789 out:1234 [done]  │  │  │                          │  ║
║  │ 2 tools, 0✗ (1.24m)       │  │  │ 3-12. Other findings...  │  ║
║  │                          │  │  │                          │  ║
║  │ malware    ████████████  │  │  │ Report: Ready            │  ║
║  │ in:4521 out:987 [done]   │  │  │ Chain of Custody: ✓      │  ║
║  │ 1 tool, 0✗ (5.12m)        │  │  │ Admissibility: ✓         │  ║
║  │                          │  │  │                          │  ║
║  │ memory     ████████████  │  │  │ [↓ Export] [↓ Share]     │  ║
║  │ in:3456 out:654 [done]   │  │  │                          │  ║
║  │ 1 tool, 0✗ (2.01m)        │  │  │ Cost: $0.0365 (FINAL)    │  ║
║  │                          │  │  ╰──────────────────────────╯  ║
║  │ network    ████████████  │  │                                ║
║  │ in:2345 out:456 [done]   │  │                                ║
║  │ 1 tool, 0✗ (1.89m)        │  │                                ║
║  ╰──────────────────────────╯  │                                ║
║                                │                                ║
║  TIMELINE (COMPLETE)           │  REPORT GENERATED              ║
║  ╭──────────────────────────╮  │  ╭──────────────────────────╮  ║
║  │ 14:00:00 Case start      │  │  │ Executive Summary:       │  ║
║  │ 14:00:05 Phase: acquire  │  │  │                          │  ║
║  │ 14:00:45 Phase: hash     │  │  │ 12 critical findings     │  ║
║  │ 14:00:50 Workers launch  │  │  │ Threat: Ransomware       │  ║
║  │ 14:06:15 Investigation   │  │  │ Actor: APT29 (87%)       │  ║
║  │          COMPLETE        │  │  │ Techniques: 5 ATT&CK     │  ║
║  │          Total: 6m 15s   │  │  │ Defenses: 8 D3FEND       │  ║
║  ╰──────────────────────────╯  │  ╰──────────────────────────╯  ║
║                                │                                ║
╠════════════════════════════════════════════════════════════════╣
║ Cost: $0.0365 (FINAL) | Tokens: 37,381 in ↓ 8,252 out ↑ | Status: ✓ Complete
╚════════════════════════════════════════════════════════════════╝

[Report saved to: /reports/RANSOMWARE-001_2026-05-22.json]
[Press q to quit or e to export]
```

---

# IMPLEMENTATION ROADMAP

## Phase 1: MVP (Week 1)

```
✅ Basic layout (4 panels)
✅ State management
✅ Queue communication
✅ Keyboard controls (q, p, r)
✅ Real-time worker tracking
✅ Simple findings display
```

## Phase 2: Polish (Week 2)

```
✅ Mouse support
✅ Modal dialogs
✅ Timeline events
✅ Drill-down views
✅ Export functionality
```

## Phase 3: Advanced (Week 3)

```
✅ Search & filter
✅ Comparison mode (multiple cases)
✅ Integration with JSONL logs (click to view)
✅ Performance profiling
✅ Theme support
```

## Phase 4: Production (Week 4)

```
✅ Error handling
✅ Recovery from disconnects
✅ Logging of TUI state
✅ Documentation
✅ Testing suite
```

---

# WHY BUILD THIS TUI?

```
Current Console Output:
  ├─ Scrolling text only
  ├─ Can't see all workers at once
  ├─ Cost only shown at end
  ├─ No interactivity
  └─ No drill-down capability

TUI Benefits:
  ✅ Real-time dashboard (5 workers visible)
  ✅ Cost tracking (live budget awareness)
  ✅ Interactivity (pause, filter, drill-down)
  ✅ Professional appearance (like commercial tools)
  ✅ Better debugging (click error → JSONL)
  ✅ Operator confidence (see what's happening)

Business Impact:
  • Reduces investigation time (faster feedback loop)
  • Improves operator experience (professional tool)
  • Enables cost control (pause if too expensive)
  • Better for demos/presentations
  • Enterprise-ready appearance
```

---

# SUMMARY: TUI FOR SIFT-MCP

```
What: Interactive Terminal Dashboard for SIFT investigations
Why: Better visibility, interactivity, cost tracking
How: Textual framework + async state management + queue communication

Key Features:
  • 5 parallel workers visible in real-time
  • 12+ findings displayed with drill-down
  • Live cost calculation and token tracking
  • Keyboard shortcuts + mouse support
  • Timeline of events + active tool details
  • Modal dialogs for detailed inspection
  • Export functionality (JSON/PDF)

Architecture:
  LangGraph workers → Queue → TUI state → Textual widgets → Screen

Libraries:
  • textual: TUI framework
  • rich: Formatting
  • asyncio: Concurrency
  • pydantic: State validation

Effort:
  MVP: 40 hours (basic dashboard)
  Production: 100 hours (full features + polish)

Next Steps:
  1. Design widget hierarchy
  2. Implement state management
  3. Create queue communication
  4. Build widgets incrementally
  5. Add interactivity
  6. Polish & test
```

