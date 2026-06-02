```
  ███████╗██╗███████╗████████╗    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
  ██╔════╝██║██╔════╝╚══██╔══╝    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
  █████╗  ██║█████╗     ██║       ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
  ██╔══╝  ██║██╔══╝     ██║       ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
  ███████╗██║██║        ██║       ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗██║
  ╚══════╝╚═╝╚═╝        ╚═╝       ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝

                     SENTINEL
                Intelligence Forensic Tools Platform
```

**Powered by Model Context Protocol (MCP) · 400+ Forensic Tools · Enterprise-Grade Analysis**

---

## Status & Badges

![Python](https://img.shields.io/badge/Python-3.10%2B-0078D4?style=flat-square&logo=python&logoColor=white)
![Framework](https://img.shields.io/badge/Framework-LangGraph-412991?style=flat-square)
![MCP](https://img.shields.io/badge/Protocol-MCP%202024--11--05-0066CC?style=flat-square)
![Tools](https://img.shields.io/badge/Tools-400%2B-15B358?style=flat-square)
![Status](https://img.shields.io/badge/Status-Production-28A745?style=flat-square)
![License](https://img.shields.io/badge/License-See%20Components-181717?style=flat-square)

---

## Overview

SIFT is an advanced digital forensics and incident response (DFIR) platform that combines AI agents with 400+ forensic analysis tools. It leverages the Model Context Protocol to enable Claude AI to orchestrate complex incident investigations across multiple forensic domains including memory analysis, disk forensics, network investigation, malware analysis, Windows forensics, and cryptographic assessment.

---

## Architecture

SIFT is composed of four primary components:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        SIFT Investigation Framework                             │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌────────────────────────────────────────────────────────────────────────┐   │
│  │  sift-agent (LangGraph Pipeline)                                       │   │
│  │  ✦ Investigation Orchestration                                        │   │
│  │  ✦ Multi-stage Forensic Workflow                                      │   │
│  │  ✦ Evidence & Finding Management                                      │   │
│  └────────────────────────────────────────────────────────────────────────┘   │
│                                         ▼                                       │
│  ┌────────────────────────────────────────────────────────────────────────┐   │
│  │  MCP Servers (Model Context Protocol)                                 │   │
│  │                                                                        │   │
│  │  attack(8)  defend(5)  disk(180)  windows(27)  network(96)           │   │
│  │  memory(5)  hashing(7)  malware(44)  crypto(28)                      │   │
│  │                                                                        │   │
│  │  400+ Forensic Tools & Binaries                                       │   │
│  └────────────────────────────────────────────────────────────────────────┘   │
│                                         ▼                                       │
│  ┌────────────────────────────────────────────────────────────────────────┐   │
│  │  Evidence & Analysis Layer                                            │   │
│  │  ✦ Disk Forensics    ✦ Memory Analysis    ✦ Network Inspection       │   │
│  │  ✦ Windows Forensics  ✦ Malware Analysis  ✦ Cryptographic Assessment │   │
│  └────────────────────────────────────────────────────────────────────────┘   │
│                                         ▼                                       │
│  ┌────────────────────────────────────────────────────────────────────────┐   │
│  │  sift-tui (Live Investigation Dashboard)                             │   │
│  │  ✦ Real-time Progress Visualization                                  │   │
│  │  ✦ Agent Activity Monitoring                                         │   │
│  │  ✦ Findings & Evidence Tracking                                      │   │
│  └────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Components

#### 1. sift-agent

The core AI-driven investigation engine built with LangGraph. Implements an agentic workflow that:
- Orchestrates evidence acquisition and analysis
- Coordinates across multiple forensic domains
- Maintains investigation state and context
- Routes analysis tasks to specialized workers
- Provides comprehensive forensic findings and attribution

**Key Files:**
- `run.py` — CLI entry point
- `graph.py` — LangGraph pipeline definition
- `state.py` — Investigation state management
- `routers.py` — Conditional routing logic
- `workers/` — Domain-specific forensic analyzers

#### 2. sift-mcp-servers

Nine independent MCP servers exposing 400+ forensic tools:

| Server | Tool Count | Focus Area |
|--------|-----------|-----------|
| sift-attack | 8 | ATT&CK threat intelligence mapping |
| sift-defend | 5 | D3FEND defensive mappings |
| sift-disk | 180 | Disk forensics and file analysis |
| sift-windows | 27 | Windows-specific forensic tools |
| sift-network | 96 | Network analysis and traffic inspection |
| sift-memory | 5 | Memory forensics tools |
| sift-hashing | 7 | Cryptographic hashing utilities |
| sift-malware | 44 | Malware analysis tools |
| sift-crypto | 28 | Cryptographic assessment tools |

Each server wraps industry-standard forensic binaries and academic tools with a standardized JSON response envelope.

#### 3. sift-tui

A live investigation dashboard built with Textual (Python TUI framework). Provides:
- Real-time investigation progress visualization
- Multi-panel layout showing agents, findings, and evidence integrity
- Tool execution stream monitoring
- Cost and token usage tracking
- Integration with sift-agent graph execution

#### 4. sift-documents

Comprehensive documentation including:
- MCP architecture and execution flows
- Agent design patterns and logging
- Tool reference guides
- Investigation workflow documentation

---

## Installation

### Prerequisites
- Python 3.10+
- WSL/Linux environment (for access to SIFT forensic binaries)
- Virtual environment manager (venv or conda)

### System Requirements

```
┌──────────────────────────────────────────────────────┐
│  SIFT System Requirements                            │
├──────────────────────────────────────────────────────┤
│  Python:      3.10+                                  │
│  Environment: WSL/Linux (Ubuntu 22.04 recommended)  │
│  Disk Space:  100GB+ (for large forensic images)    │
│  RAM:         8GB minimum (16GB recommended)        │
│  CPU Cores:   4+ (for parallel tool execution)      │
└──────────────────────────────────────────────────────┘
```

### Quick Start

1. **Clone the repository**
```bash
cd SIFT\ -\ Sentinel
```

2. **Set up the virtual environment**
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. **Install sift-agent dependencies**
```bash
cd sift-agent
pip install -r requirements.txt
cd ..
```

4. **Install sift-mcp-servers**
```bash
cd sift-mcp-servers/servers
pip install -e .
cd ../..
```

5. **Configure MCP servers** (optional for enhanced analysis)
```bash
cp sift-mcp-servers/servers/claude_desktop_config.json ~/.config/Claude/claude_desktop_config.json
```

---

## Usage

### Investigation Workflow

```
START
  │
  ├─ Acquisition ─────────────── Gather forensic evidence from target systems
  │      │
  ├─ Hashing ───────────────────── Compute SHA-256 hashes for integrity verification
  │      │
  ├─ Analysis ──────────────────── Execute forensic analysis across all domains
  │      │                          • Disk analysis
  │      │                          • Memory forensics
  │      │                          • Network traffic
  │      │                          • Malware analysis
  │      │                          • Windows forensics
  │      │                          • Cryptographic assessment
  │      │
  ├─ Attribution ──────────────── Map findings to ATT&CK techniques & threat actors
  │      │
  ├─ Defense ──────────────────── Generate defensive recommendations (D3FEND)
  │      │
  └─ Reporting ────────────────── Compile comprehensive findings & evidence chain-of-custody
         │
       COMPLETE
```

### CLI Investigation

```bash
cd sift-agent
python run.py --case-id incident-001 --evidence /path/to/evidence/
```

**Options:**
- `--case-id` — Unique investigation identifier
- `--evidence` — Path to forensic evidence files
- `--output` — Output directory for findings (default: ./results)

### Interactive Dashboard

```bash
cd sift-tui
python tui.py --case-id incident-001 --evidence /path/to/evidence/
```

The dashboard provides real-time visualization of:
- Investigation stages (acquire → hash → analyze → attribute → defend → complete)
- Active forensic agents and tool execution
- Findings and evidence integrity verification
- Token usage and cost estimation

### Verification and Testing

From `sift-mcp-servers/`:

```bash
# Verify all 9 MCP servers load correctly
python verify.py

# Test attack and defense intelligence mappings
python verify_attack_defend.py

# Audit all forensic binaries
python audit_tools.py

# Generate performance and coverage report
python phase5_report.py
```

---

## Project Structure

```
SIFT - Sentinel/
├── sift-agent/              # AI-driven investigation engine (LangGraph)
│   ├── workers/             # Domain-specific forensic analyzers
│   ├── graph.py             # Investigation pipeline
│   ├── state.py             # Investigation context management
│   └── run.py               # CLI entry point
│
├── sift-mcp-servers/        # MCP server implementations (400+ tools)
│   ├── servers/             # 9 server implementations
│   ├── verify.py            # Server verification suite
│   └── logs/                # Tool execution logs (JSONL)
│
├── sift-tui/                # Terminal UI dashboard
│   ├── tui.py               # Textual UI implementation
│   └── mock_run.py          # Demo mode
│
├── sift-documents/          # Comprehensive documentation
│   ├── MCP-AGENT-FLOW-COMPLETE.md
│   ├── SIFT-TOOLS-COMPLETE-GUIDE.md
│   └── README.md
│
└── sift-datasets/           # Sample forensic evidence
```

---

## Key Features

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ SIFT Enterprise-Grade Capabilities                                          │
├──────────────────────────────┬─────────────────────────────────────────────┤
│ COMPREHENSIVE TOOLING        │ INTELLIGENT ANALYSIS                        │
│ ✓ 400+ forensic tools        │ ✓ AI-driven orchestration                  │
│ ✓ 9 specialized servers      │ ✓ Multi-domain coordination                │
│ ✓ Industry-standard binaries │ ✓ Automated workflow management            │
│ ✓ Academic research tools    │ ✓ Context-aware investigation              │
├──────────────────────────────┼─────────────────────────────────────────────┤
│ EVIDENCE INTEGRITY           │ THREAT INTELLIGENCE                         │
│ ✓ Automatic hash verification│ ✓ ATT&CK technique mapping                 │
│ ✓ Chain-of-custody tracking  │ ✓ Threat actor attribution                 │
│ ✓ Cryptographic validation   │ ✓ D3FEND defensive mappings                │
│ ✓ Forensic audit trails      │ ✓ TTP correlation analysis                 │
├──────────────────────────────┼─────────────────────────────────────────────┤
│ REAL-TIME VISIBILITY         │ EXTENSIBILITY & STANDARDS                   │
│ ✓ Live progress dashboards   │ ✓ MCP protocol integration                  │
│ ✓ Agent activity monitoring  │ ✓ Pluggable tool interface                  │
│ ✓ Finding stream tracking    │ ✓ Standardized response envelopes          │
│ ✓ Cost & token tracking      │ ✓ Reproducible analysis workflows          │
└──────────────────────────────┴─────────────────────────────────────────────┘
```

### Capabilities

- **Comprehensive Tool Coverage** — 400+ forensic tools across 9 specialized domains
- **AI-Driven Analysis** — Claude AI coordinates complex multi-stage investigations
- **Evidence Integrity** — Automatic hash verification and chain-of-custody tracking
- **Threat Attribution** — Integrated ATT&CK and D3FEND mappings for contextual threat intelligence
- **Real-Time Dashboarding** — Live progress visualization during investigations
- **Standardized Interface** — MCP-based tool wrapping for extensibility
- **Reproducible Workflows** — Full logging and audit trails for all operations

---

## Documentation

For detailed information, see:

- [MCP Architecture & Agent Flow](./sift-documents/MCP-AGENT-FLOW-COMPLETE.md) — Complete execution timeline and data flow
- [Logging & Instrumentation](./sift-documents/MCP-AGENT-LOGGING-EXPLAINED.md) — Event streaming and observability
- [Tool Reference](./sift-mcp-servers/Sift-MCP-Tools.md) — All 400+ tools with parameters and examples
- [TUI Design Guide](./sift-documents/SIFT-MCP-TUI-DESIGN-GUIDE.md) — Dashboard architecture and customization

---

## Requirements

- Python 3.10 or later
- DFIR toolchain (pre-installed in WSL/Linux image)
- Internet access for MCP initialization
- Sufficient disk space for large forensic images (100GB+ recommended)

---

## Performance

- **Typical small investigation** — 2-4 hours
- **Complex multi-system incident** — 4-8 hours
- **Tool execution overhead** — 50ms-5s per tool (depends on tool complexity)
- **Token usage** — 50k-100k tokens per investigation

---

## Contributing

Contributions are welcome. Please ensure:
- New tools are wrapped through appropriate MCP servers
- All tools include standardized response envelopes
- Tool verification tests pass
- Documentation is updated accordingly

---

## Support

For issues, documentation clarifications, or tool-specific questions:

1. Check [sift-documents/](./sift-documents/) for architectural guidance
2. Review [sift-mcp-servers/logs/](./sift-mcp-servers/logs/) for execution traces
3. Run verification suite to validate environment setup

---

## License

See individual component directories for licensing information.

---

## Version & Support

```
┌──────────────────────────────────────────────────────┐
│  SIFT Sentinel Intelligence Forensic Tools           │
│                                                      │
│  Version:     1.0                                    │
│  Release:     June 2026                              │
│  Status:      Production Ready                       │
│  Support:     Documentation & Community              │
└──────────────────────────────────────────────────────┘
```

---

**Developed with enterprise-grade security and forensic integrity standards**
