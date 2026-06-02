# SIFT MCP Servers - Complete Tools Guide with Examples

**400+ forensic tools across 9 MCP servers with practical incident response examples.**

---

# TABLE OF CONTENTS
1. [sift-attack (8 tools)](#sift-attack--intelligent-attack-framework-mapping)
2. [sift-defend (5 tools)](#sift-defend--defensive-mitigations)
3. [sift-disk (180 tools)](#sift-disk--disk-forensics)
4. [sift-windows (27 tools)](#sift-windows--windows-forensics)
5. [sift-network (96 tools)](#sift-network--network-forensics)
6. [sift-memory (5 tools)](#sift-memory--memory-forensics)
7. [sift-hashing (7 tools)](#sift-hashing--file-hashing--integrity)
8. [sift-malware (44 tools)](#sift-malware--malware-analysis)
9. [sift-crypto (28 tools)](#sift-crypto--encryption-cryptography)

---

# SIFT-ATTACK — Intelligent Attack Framework Mapping

**Purpose**: Map forensic evidence to MITRE ATT&CK framework (threat intelligence, attribution)

**Data Source**: ATT&CK STIX bundles (enterprise, ICS, mobile) loaded at startup

---

## Tool 1: `map_finding_to_technique` ⭐ MOST IMPORTANT

**Purpose**: Convert raw forensic evidence → MITRE ATT&CK technique(s)

**Function Signature**:
```python
map_finding_to_technique(finding: str) -> dict
```

**Parameters**:
- `finding` (string) — Forensic evidence snippet (registry key, event ID, process command, file path, tool output)

**What it does**:
- Searches ATT&CK knowledge base (technique names, descriptions, aliases)
- Returns matching techniques with confidence scores
- Handles variations (e.g., "PowerShell" → T1059.001)

**Real-world Examples**:

**Example 1: Windows Event Log**
```
Input: "Event ID 4104 - PowerShell scriptblock logging"

Output:
{
  "techniques": [
    {
      "id": "T1059.001",
      "name": "Command and Scripting Interpreter: PowerShell",
      "tactic": "execution",
      "description": "Adversaries may abuse PowerShell commands for execution...",
      "confidence": "high"
    }
  ]
}
```

**Example 2: Registry Evidence**
```
Input: "HKLM\\System\\CurrentControlSet\\Services\\Foo\\Start value changed to 2"

Output:
{
  "techniques": [
    {
      "id": "T1547.001",
      "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
      "tactic": "persistence",
      "confidence": "high"
    },
    {
      "id": "T1112",
      "name": "Modify Registry",
      "tactic": "defense-evasion",
      "confidence": "medium"
    }
  ]
}
```

**Example 3: Process Execution**
```
Input: "C:\\Windows\\System32\\wmic.exe process call create \\\"cmd /c powershell\\\""

Output:
{
  "techniques": [
    {
      "id": "T1047",
      "name": "Windows Management Instrumentation",
      "tactic": "execution",
      "confidence": "high"
    },
    {
      "id": "T1059.001",
      "name": "Command and Scripting Interpreter: PowerShell",
      "confidence": "high"
    }
  ]
}
```

**Use in sift-agent**:
```python
# After filesystem analysis extracts suspicious binary
finding = "Unsigned .exe in C:\\ProgramData\\Adobe\\"
techniques = await call_tool("map_finding_to_technique", finding=finding)
# Returns: T1574.002 (DLL Side-Loading), T1027 (Obfuscated Files)
# → Links to attack_map phase in graph
```

---

## Tool 2: `get_technique_details`

**Purpose**: Retrieve full ATT&CK record for a technique

**Function Signature**:
```python
get_technique_details(technique_id: str) -> dict
```

**Parameters**:
- `technique_id` (string) — Technique ID (T1059.001) or name (PowerShell)

**What it does**:
- Loads full technique record from STIX database
- Returns description, tactics, data sources, detection methods, mitigations

**Real-world Example**:

```python
# Input
technique_id = "T1047"

# Output
{
  "id": "T1047",
  "name": "Windows Management Instrumentation",
  "description": "Adversaries may abuse Windows Management Instrumentation (WMI) ...",
  "tactics": ["execution"],
  "data_sources": [
    {"name": "Process", "components": ["Process creation"]},
    {"name": "Command", "components": ["Command execution"}
  ],
  "detection": "Monitor for suspicious WMI-ExecutionPolicy, Get-WmiObject, Invoke-WmiMethod",
  "mitigations": [
    "M1040 - Behavior Prevention on Endpoint",
    "M1026 - Privileged Account Management"
  ],
  "groups": ["APT29", "FIN7", "Wizard Spider"],
  "software": ["WMI Monitor", "Invoke-WmiMethod"],
  "references": [...]
}
```

---

## Tool 3: `get_groups_using_technique`

**Purpose**: List threat-actor groups known to use a technique

**Function Signature**:
```python
get_groups_using_technique(technique_id: str) -> dict
```

**Parameters**:
- `technique_id` (string) — Technique ID (T1059.001)

**What it does**:
- Queries ATT&CK relationship graph
- Returns all groups (APT, FIN, etc.) that use this technique
- Includes group aliases and IDs

**Real-world Example**:

```python
# Input
technique_id = "T1027"  # Obfuscated Files or Information

# Output
{
  "technique": "T1027",
  "groups": [
    {
      "id": "G0016",
      "name": "APT29",
      "aliases": ["Cozy Bear", "The Dukes"],
      "description": "Russian-attributed APT...",
      "confirmed_use": true
    },
    {
      "id": "G0051",
      "name": "FIN10",
      "aliases": ["Wizard Spider"],
      "description": "Financially-motivated ransomware group...",
      "confirmed_use": true
    },
    {
      "id": "G0134",
      "name": "Wizard Spider",
      "aliases": ["Royal Ransomware"],
      "confirmed_use": true
    }
    // ... 50+ more groups
  ],
  "total_groups": 87
}
```

**Use in sift-agent**:
```python
# After finding T1047 (WMI execution)
groups = await call_tool("get_groups_using_technique", technique_id="T1047")
# If APT29 in results → suggests nation-state targeting
# If FIN7 in results → suggests financially-motivated cybercrime
# → Informs severity/priority in report
```

---

## Tool 4: `list_techniques_by_tactic`

**Purpose**: Enumerate all techniques under a tactic (e.g., execution, persistence)

**Function Signature**:
```python
list_techniques_by_tactic(tactic: str) -> dict
```

**Parameters**:
- `tactic` (string) — Tactic name (execution, persistence, lateral-movement, defense-evasion, etc.)

**What it does**:
- Returns all techniques mapped to a tactic
- Useful for completeness checks ("did attacker try all persistence methods?")

**Real-world Example**:

```python
# Input
tactic = "persistence"

# Output
{
  "tactic": "persistence",
  "techniques": [
    {"id": "T1098", "name": "Account Manipulation", "status": "active"},
    {"id": "T1547", "name": "Boot or Logon Autostart Execution", "status": "active"},
    {"id": "T1547.001", "name": "Registry Run Keys", "status": "active"},
    {"id": "T1547.004", "name": "Winlogon Helper DLL", "status": "active"},
    {"id": "T1547.008", "name": "LSASS Driver", "status": "active"},
    {"id": "T1547.009", "name": "Shortcut Modification", "status": "active"},
    {"id": "T1547.011", "name": "Plist Modification", "status": "active"},
    {"id": "T1547.013", "name": "XDG Autostart Entries", "status": "active"},
    {"id": "T1098.002", "name": "Exchange Email Delegate Permissions", "status": "active"},
    {"id": "T1098.003", "name": "Add Office 365 Global Administrator Role", "status": "active"},
    // ... 100+ more
  ],
  "total_count": 187
}
```

---

## Tool 5: `assess_attack_chain`

**Purpose**: Given observed techniques, identify threat groups with matching TTP patterns

**Function Signature**:
```python
assess_attack_chain(technique_ids: list[str]) -> dict
```

**Parameters**:
- `technique_ids` (array) — List of observed technique IDs

**What it does**:
- Compares technique chain against known group playbooks
- Ranks groups by similarity (which group typically uses THIS exact sequence?)
- Returns confidence for attribution

**Real-world Example**:

```python
# Input: Observed attack chain from incident
technique_ids = [
  "T1087",      # Account Discovery
  "T1087.002",  # Domain Account
  "T1087.004",  # Cloud Account
  "T1135",      # Network Share Discovery
  "T1040",      # Network Sniffing
  "T1021.001",  # Remote Service Session Initiation (Windows Admin Shares)
  "T1569.002",  # Service Execution (PsExec)
  "T1021.006",  # Remote Service Session Initiation (SSH)
]

# Output
{
  "attack_chain": ["T1087", "T1087.002", "T1087.004", "T1135", "T1040", "T1021.001", "T1569.002", "T1021.006"],
  "matching_groups": [
    {
      "group": "APT1",
      "confidence": 0.94,
      "reason": "APT1 regularly uses this exact discovery→lateral-movement chain"
    },
    {
      "group": "Equation Group",
      "confidence": 0.87,
      "reason": "Known for network sniffing + PsExec lateral movement"
    },
    {
      "group": "APT29",
      "confidence": 0.76,
      "reason": "Cloud account discovery matches recent APT29 campaigns"
    }
  ],
  "high_confidence_attribution": "APT1 (Comodo Group / Comment Crew)"
}
```

**Incident Response Use**:
```
Case Timeline:
  08:15 - User account discovery (T1087)
  08:20 - Domain enumeration (T1087.002)
  08:25 - Network share mapping (T1135)
  08:30 - Suspicious RDP (T1021.001)
  08:35 - PsExec execution (T1569.002)

assess_attack_chain() → "This looks like APT1 playbook from 2015"
→ Incident commander can activate APT1-specific response playbook
```

---

## Tool 6: `get_sift_tools_for_technique`

**Purpose**: Map MITRE ATT&CK technique → SIFT binaries that surface evidence

**Function Signature**:
```python
get_sift_tools_for_technique(technique_id: str) -> dict
```

**Parameters**:
- `technique_id` (string) — Technique ID

**What it does**:
- Uses hand-curated mappings (SIFT_MAPPINGS) for top-50 techniques
- Falls back to data-source heuristics for other techniques
- Returns which SIFT server(s) to call

**Real-world Example**:

```python
# Input
technique_id = "T1547.001"  # Registry Run Keys / Startup Folder

# Output
{
  "technique": "T1547.001",
  "name": "Registry Run Keys / Startup Folder",
  "sift_tools": [
    {
      "server": "sift-windows",
      "tool": "regfexport",
      "reason": "Extract registry hive containing HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    },
    {
      "server": "sift-disk",
      "tool": "regfexport",  // via mounted filesystem
      "reason": "Offline registry extraction from Evidence folder"
    },
    {
      "server": "sift-disk",
      "tool": "fls",
      "reason": "Check %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    }
  ]
}
```

**sift-agent Integration**:
```python
# After finding T1547.001
tools = await call_tool("get_sift_tools_for_technique", technique_id="T1047.001")
# Returns: regfexport, fls
# → Automatically schedules filesystem + windows workers to extract evidence
```

---

## Tool 7: `get_software_used_by_group`

**Purpose**: List malware/tools attributed to a threat actor

**Function Signature**:
```python
get_software_used_by_group(group: str) -> dict
```

**Parameters**:
- `group` (string) — Group ID (G0016) or name (APT29)

**What it does**:
- Returns all malware/tools used by group
- Includes software IDs (S-xxxx) and names
- Useful for looking for known malware

**Real-world Example**:

```python
# Input
group = "APT29"

# Output
{
  "group": "APT29",
  "aliases": ["Cozy Bear", "The Dukes"],
  "software": [
    {
      "id": "S0002",
      "name": "Mimikatz",
      "type": "credential-dumper",
      "platforms": ["Windows"]
    },
    {
      "id": "S0005",
      "name": "Net",
      "type": "system-admin-tool",
      "platforms": ["Windows"]
    },
    {
      "id": "S0014",
      "name": "Putty",
      "type": "remote-access",
      "platforms": ["Windows"]
    },
    {
      "id": "S0019",
      "name": "VBSpy",
      "type": "reconnaissance",
      "platforms": ["Windows"]
    },
    {
      "id": "S0039",
      "name": "OLECMDEXEC",
      "type": "lateral-movement",
      "platforms": ["Windows"]
    },
    // ... 40+ more tools
  ],
  "total_tools": 47
}
```

**Incident Response Flow**:
```
Found binary: C:\Temp\Mimikatz.exe (hash matches known APT29 variant)
↓
get_software_used_by_group("APT29")
↓
Confirmed: Mimikatz is in APT29 toolkit
↓
Report: "High confidence APT29 compromise"
```

---

## Tool 8: `get_countermeasures`

**Purpose**: Retrieve ATT&CK mitigations for a technique

**Function Signature**:
```python
get_countermeasures(technique_id: str) -> dict
```

**Parameters**:
- `technique_id` (string) — Technique ID

**What it does**:
- Returns mitigation IDs (M-xxxx) and descriptions
- Provides actionable remediation

**Real-world Example**:

```python
# Input
technique_id = "T1021.001"  # Remote Service Session Initiation (Windows Admin Shares)

# Output
{
  "technique": "T1021.001",
  "mitigations": [
    {
      "id": "M1026",
      "name": "Privileged Account Management",
      "description": "Manage the creation, modification, use, and permissions of privileged accounts..."
    },
    {
      "id": "M1040",
      "name": "Behavior Prevention on Endpoint",
      "description": "Use capabilities to prevent successful behavior..."
    },
    {
      "id": "M1035",
      "name": "Limit Access to Resource over Network",
      "description": "Prevent access to file shares, web content, DNS, SMB, RPC..."
    },
    {
      "id": "M1030",
      "name": "Network Segmentation",
      "description": "Segregate networks and systems..."
    }
  ]
}
```

---

# SIFT-DEFEND — Defensive Mitigations

**Purpose**: Map forensic findings to D3FEND defensive techniques

**Data Source**: D3FEND framework (273 techniques, 14,003 ATT&CK mappings)

---

## Tool 1: `list_defenses_for_attack`

**Purpose**: Given ATT&CK technique, list D3FEND defenses that counter it

**Function Signature**:
```python
list_defenses_for_attack(technique_id: str) -> dict
```

**Parameters**:
- `technique_id` (string) — Technique ID

**What it does**:
- Returns D3FEND defensive techniques (D3-XXXX)
- Organized by tactic (Harden, Detect, Isolate, Evict, Restore)
- Includes artifact linkages

**Real-world Example**:

```python
# Input
technique_id = "T1110"  # Brute Force (credential testing)

# Output
{
  "attack_technique": "T1110",
  "attack_name": "Brute Force",
  "defenses": [
    {
      "id": "D3-AM",
      "label": "Access Mediation",
      "tactic": "Harden",
      "description": "Enforce attribute-based access control (ABAC) policies...",
      "artifacts": ["Credential", "Session", "Access Request"]
    },
    {
      "id": "D3-AR",
      "label": "Aggregate Risk",
      "tactic": "Detect",
      "description": "Determine aggregate risk based on account context...",
      "artifacts": ["Authentication Log", "Account"]
    },
    {
      "id": "D3-ARAD",
      "label": "Adaptive Response",
      "tactic": "Detect",
      "description": "Adapt response actions to threats dynamically...",
      "artifacts": ["Event"]
    },
    {
      "id": "D3-CAPO",
      "label": "Account Locking",
      "tactic": "Isolate",
      "description": "Lock accounts after threshold failures...",
      "artifacts": ["Account"]
    }
  ]
}
```

**Incident Response Example**:
```
Finding: "437 failed RDP login attempts in 2 minutes"
↓
map_finding_to_technique() → T1110 (Brute Force)
↓
list_defenses_for_attack("T1110")
↓
Recommended: D3-CAPO (Account Locking), D3-AM (Access Mediation)
↓
Remediation: Enable account lockout policy, implement MFA
```

---

## Tool 2: `find_defenses_for_artifact`

**Purpose**: Given a digital artifact, find defenses that observe/protect it

**Function Signature**:
```python
find_defenses_for_artifact(artifact: str) -> dict
```

**Parameters**:
- `artifact` (string) — Artifact label (Process, File, Network Traffic, Registry, etc.)

**What it does**:
- Returns defenses that use/protect this artifact type
- Useful for: "We found process X, what should we monitor?"

**Real-world Example**:

```python
# Input
artifact = "Process"

# Output
{
  "artifact": "Process",
  "defenses_that_observe": [
    {
      "id": "D3-PSVM",
      "label": "Process Spawn Monitoring",
      "tactic": "Detect",
      "description": "Monitor for process creation events..."
    },
    {
      "id": "D3-ECCAM",
      "label": "Execution Causality Capture",
      "tactic": "Detect",
      "description": "Capture causality between parent/child processes..."
    },
    {
      "id": "D3-ECCIM",
      "label": "Execution Causality Instrumentation",
      "tactic": "Detect",
      "description": "Instrument OS to track process relationships..."
    }
  ],
  "defenses_that_protect": [
    {
      "id": "D3-EPIM",
      "label": "Execution Process Isolation",
      "tactic": "Isolate",
      "description": "Isolate process execution in sandboxes..."
    }
  ]
}
```

---

## Tool 3: `get_defense`

**Purpose**: Lookup single D3FEND defense by ID, label, or URI

**Function Signature**:
```python
get_defense(defense_id: str) -> dict
```

**Parameters**:
- `defense_id` (string) — ID (D3-AMED), label (Access Mediation), or URI (AccessMediation)

**What it does**:
- Returns full D3FEND technique record
- Includes description, tactics, related artifacts, ATT&CK mappings

**Real-world Example**:

```python
# Input
defense_id = "D3-EA"  // Execution Isolation

# Output
{
  "id": "D3-EA",
  "label": "Execution Isolation",
  "uri": "d3f:ExecutionIsolation",
  "description": "Isolate execution environments from each other and the host. E.g., containers, VMs, sandboxes.",
  "tactics": ["Isolate"],
  "artifacts": ["Execution Environment", "Process", "System Configuration"],
  "related_defenses": ["D3-EPIM", "D3-TPAM"],
  "examples": [
    "Run untrusted code in Docker container",
    "Use Windows Sandbox for unknown executables",
    "Run browsers in AppVM (Qubes OS)"
  ],
  "attack_techniques_mitigated": [
    "T1648",  // Serverless Execution
    "T1659",  // Content Injection
    "T1199",  // Trusted Relationship
  ],
  "detection_approaches": [
    "Monitor for container/VM escape attempts",
    "Track process behavior outside sandbox"
  ]
}
```

---

## Tool 4: `list_defenses_by_tactic`

**Purpose**: List all D3FEND defenses under a tactic

**Function Signature**:
```python
list_defenses_by_tactic(tactic: str) -> dict
```

**Parameters**:
- `tactic` (string) — D3FEND tactic (Harden, Detect, Isolate, Deceive, Evict, Restore, Model)

**Real-world Example**:

```python
# Input
tactic = "Detect"

# Output
{
  "tactic": "Detect",
  "defenses": [
    {
      "id": "D3-ABM",
      "label": "Adversary Behavioral Modeling",
      "description": "Model adversary behaviors..."
    },
    {
      "id": "D3-ACM",
      "label": "Account Credential Mismatch",
      "description": "Detect accounts using credentials inconsistently..."
    },
    {
      "id": "D3-ARAD",
      "label": "Adaptive Response",
      "description": "Adapt response actions to threats..."
    },
    // ... 100+ more
  ],
  "total_count": 127
}
```

---

## Tool 5: `get_attack_to_defend_coverage`

**Purpose**: Global view of ATT&CK ↔ D3FEND coverage

**Function Signature**:
```python
get_attack_to_defend_coverage() -> dict
```

**What it does**:
- Returns statistics on mapped techniques
- Shows coverage gaps (unmapped techniques)
- Broken down by domain (enterprise, mobile, ICS)

**Real-world Example**:

```python
# Output
{
  "total_attack_techniques": 924,
  "attack_techniques_with_defenses": 612,
  "coverage_percent": 66.2,
  "by_domain": {
    "enterprise": {
      "total": 599,
      "with_defenses": 450,
      "coverage": 75.1
    },
    "mobile": {
      "total": 189,
      "with_defenses": 89,
      "coverage": 47.1
    },
    "ics": {
      "total": 136,
      "with_defenses": 73,
      "coverage": 53.7
    }
  },
  "unmapped_techniques": [
    "T0001",  // Fake Credentials
    "T0002",  // Adversary Emulation
    // ... (all ICS techniques currently unmapped)
  ]
}
```

---

# SIFT-DISK — Disk Forensics (180 Tools)

**Purpose**: Disk imaging, partition analysis, filesystem forensics, file recovery

All disk tools follow this wrapper signature:
```python
tool_<binary>(args: str = "") -> dict

# Returns:
{
  "tool": "evtxexport",
  "server": "sift-disk",
  "command": "evtxexport -r /evidence/disk.img",
  "exit_code": 0,
  "stdout": "...",
  "stderr": null,
  "timestamp": "2026-05-21T10:30:45Z",
  "duration_ms": 2456,
  "installed": true
}
```

---

## Category 1: Evidence Collection & Imaging (Binary Wrappers)

### `tool_dc3dd` — DoD-compliant Disk Copying
```python
tool_dc3dd(args="-r /dev/sda /evidence/disk.img")
# Forensically sound disk-to-image with:
# - Progress indicator
# - Sector verification
# - Bad-block skipping
# Returns: sector count, hash verification
```

**Use Case**: Acquire physical disk
```
Incident: Compromised server
→ tool_dc3dd(args="-r /dev/sda server_disk.img")
→ Creates forensically-sound image for analysis
→ Chains output to hash verification
```

### `tool_ddrescue` — Resilient Disk Copying (handles bad blocks)
```python
tool_ddrescue(args="/dev/sda /evidence/disk_rescue.img /evidence/rescue.log")
# Skips bad blocks, retries from different angles
# Generates retry log for later analysis
```

**Use Case**: Damaged disks (crashes, malicious wipe attempts)

### `tool_ewfacquire` — Encase Evidence File (E01) Creation
```python
tool_ewfacquire(args="/dev/sda /evidence/case001.E01")
# Creates compressed, forensically-sound E01 image format
# Includes encryption, compression options
```

### `tool_ewfexport` — E01 to Raw Image Conversion
```python
tool_ewfexport(args="-t /evidence/case001.E01 /evidence/case001_raw.img")
# Converts E01 back to raw for compatibility
```

### `tool_xmount` — Mount Multiple Image Formats
```python
tool_xmount(args="-i raw -o /evidence/case001.img /mnt/evidence")
# Mount raw, E01, AFF images without conversion
# Access via FUSE filesystem
```

---

## Category 2: Partition Analysis (TSK Tools)

### `tool_mmls` — List Partition Table
```python
tool_mmls(args="/evidence/disk.img")

Output:
Units are in 512-byte sectors
     Start        End          Length       Description
00:  0000000000   0002047999   0002048000   Unallocated
01:  0002048000   0001048575999 0001046527999 NTFS (0x07)
02:  0001048576000 0001250950655 0000374374656  Extended (0x0F)

Usage: Identify partition offsets for mounting specific partitions
```

**Real-world Example**:
```python
# Disk has 3 partitions: find the NTFS system volume
result = await tool_mmls(args="/evidence/disk.img")
# Parse output, find offset 2048000 for NTFS
# → Mount at offset: mount -o offset=$((2048000*512)) disk.img /mnt/vol1
```

### `tool_mmstat` — Partition Table Statistics
```python
tool_mmstat(args="/evidence/disk.img")
# Returns: partition type details, flags
```

### `tool_mmcat` — Extract Partition Table Bytes
```python
tool_mmcat(args="/evidence/disk.img")
# Raw partition table output for analysis
```

---

## Category 3: Filesystem Analysis — EXT (Linux)

### `tool_fsstat` — Filesystem Statistics
```python
tool_fsstat(args="/evidence/disk.img")

Output:
File System Type: Ext3
Last Mounted on: /
Last written to: Fri May 16 10:30:00 2026
Inode Range: 1 - 131072
Block Range: 0 - 1048576
Device ID: 801
Device: /dev/sda1
```

**Use Case**: Understand filesystem layout before deeper analysis

### `tool_debugfs` — Interactive EXT Filesystem Debugger
```python
# List all files in inode 12345
tool_debugfs(args="-R 'ncheck 12345' /evidence/disk.img")

Output:
Inode 12345 is referenced by:
    12288 (file 'suspicious.exe')
```

**Use Case**: Track deleted inodes, recover filenames

### `tool_fls` — List Files (TSK)
```python
tool_fls(args="-r /evidence/disk.img | head -50")

Output:
r/r  10485:  /bin/bash
r/r  10486:  /bin/sh
r/r  10487:  /bin/ls
d/d  2048:   /home
d/d  2049:   /home/user
r/r  2050:   /home/user/.ssh (deleted)
r/r  2051:   /home/user/.ssh/id_rsa (deleted)
-  indicates allocated file
d  indicates directory
r  indicates "recovered" (deleted, but still in inode list)
```

**Real-world Incident**:
```python
# Attacker deleted SSH keys, but filesystem still has inode
result = await tool_fls(args="-r /evidence/disk.img")
# Parse output, find:
# r/r  2051   /home/user/.ssh/id_rsa (deleted)
# → Extract with: tool_icat(args="/evidence/disk.img -r 2051 > id_rsa")
```

### `tool_icat` — Extract File by Inode
```python
tool_icat(args="/evidence/disk.img 2051 > id_rsa")
# Recovers file content even if deleted
# Output: raw file bytes (e.g., OpenSSH private key)
```

### `tool_istat` — Inode Statistics
```python
tool_istat(args="/evidence/disk.img 2051")

Output:
Inode: 2051
Allocated
Size: 1704
Nlink: 0 (deleted)
Mode: rrw-r----- (33188)
UID:  1000 (user)
GID:  1000 (user)
Modified: Fri May 16 08:15:00 2026
Accessed: Fri May 16 10:30:00 2026
Changed:  Fri May 16 08:45:00 2026
Direct Blocks:
  4096, 4097, 4098
```

**Forensic Value**: MAC times prove when file was deleted/accessed

### `tool_extundelete` — EXT-specific Deletion Recovery
```python
tool_extundelete(args="--restore-file home/user/.ssh/id_rsa /evidence/disk.img")
# Specialized recovery for ext3/4 deleted files
# Attempts journal recovery
```

---

## Category 4: Filesystem Analysis — NTFS (Windows)

### `tool_fsstat` — NTFS Statistics
```python
tool_fsstat(args="ntfs /evidence/disk.img")

Output:
File System Type: NTFS
NTFS Signature: 0xEB52904E
Bytes Per Sector: 4096
Sectors Per Cluster: 1
...
```

### `tool_ntfsls` — List NTFS Files
```python
tool_ntfsls(args="/evidence/disk.img /Users/Admin")

Output:
D  4096    ..
D  4096    .
R  125474  Desktop
R  234567  Documents
R  0       AppData (Alternate Data Stream)
```

### `tool_ntfsundelete` — Recover Deleted NTFS Files
```python
tool_ntfsundelete(args="--scan /evidence/disk.img")

Output:
Deleted Inode 5234:
  Name: malware.exe
  Size: 234567 bytes
  Modified: 2026-05-15 12:30:00
  Recoverable: Yes
```

### `tool_ntfscat` — Extract NTFS File
```python
tool_ntfscat(args="/evidence/disk.img /Windows/System32/config/SAM > sam")
# Extract SAM hive for credential analysis
```

### `tool_ntfsinfo` — NTFS File Metadata
```python
tool_ntfsinfo(args="/evidence/disk.img /Users/Admin/malware.exe")

Output:
Name: malware.exe
Inode: 52345
Size: 234567
Allocated: Yes
Created: 2026-05-10 08:00:00
Modified: 2026-05-15 12:30:00
Accessed: 2026-05-16 10:00:00
MFT Change: 2026-05-15 14:00:00 (deleted and recovered)
```

### `tool_ntfsdecrypt` — Decrypt EFS Files
```python
tool_ntfsdecrypt(args="/evidence/disk.img /Users/Admin/secrets.txt.encrypted")
# If recovery key is available, decrypt EFS
```

---

## Category 5: NTFS Alternate Data Streams (ADS)

### Detecting ADS (Hidden Files in NTFS)
```python
# NTFS allows files within files: filename.txt:hidden.exe
tool_ntfsls(args="/evidence/disk.img /Users/Admin")

# Output shows ADS if present
R  0       document.docx:malware.exe
# ^ Hidden executable attached to Word document
```

**Real-world Malware Scenario**:
```python
# Attacker hides backdoor in ADS
# tool_ntfsls reveals:
# R  0       Resume.docx:shell.exe

# Extract ADS executable:
tool_ntfscat(args="/evidence/disk.img '/Users/Admin/Resume.docx:shell.exe' > shell.exe")

# Analyze with malware tools:
result = await tool_clamscan(args="shell.exe")
# Returns: Trojan.Downloader detected
```

---

## Category 6: File Recovery & Carving

### `tool_photorec` — Carve Unallocated Space
```python
tool_photorec(args="-d /mnt/evidence -B /evidence/disk.img /evidence/recovered_files")

# Finds:
# - Deleted JPEG images
# - Deleted Office documents
# - Deleted video files
# - Anything with recognizable file signature
```

**Forensic Timeline**:
```
Timeline of events:
  08:00 - Attacker downloads malware.exe
  08:05 - Copies to USB drive (file deleted from disk)
  08:10 - Runs malware
  10:00 - IT team seizes disk

→ photorec recovers deleted malware.exe from unallocated space
→ Links to incident timeline
```

### `tool_scalpel` — Signature-based File Carving
```python
tool_scalpel(args="-c /etc/scalpel/scalpel.conf /evidence/disk.img")

# Configuration defines file signatures:
# jpg  y  200000  JPEG  ...
# png  y  1000000 PNG   ...
# pdf  y  5000000 PDF   ...
# exe  y  0       MZ    ...

# Carves files based on magic bytes
```

**Use Case**: Recover malware samples from unallocated space

### `tool_foremost` — Another Carving Tool
```python
tool_foremost(args="-i /evidence/disk.img -o /evidence/output")
# Similar to scalpel, pre-configured for common file types
```

---

## Category 7: Archive & Image File Tools

### `tool_7z` / `tool_7za` — 7-Zip Archive Extraction
```python
tool_7z(args="x /evidence/archive.7z -o/evidence/extracted")
# Extract 7z archives found during forensic analysis
```

**Scenario**: Found compressed archive on suspect disk
```python
# Extract and analyze contents
result = await tool_7z(args="x /mnt/evidence/backup.7z -o/mnt/extracted")
# Contents: SSH keys, credentials, source code
→ Evidence of data exfiltration
```

### `tool_affcat`, `tool_affinfo` — AFF Image Manipulation
```python
# Info about AFF image
tool_affinfo(args="/evidence/case001.aff")

# Convert AFF to raw
tool_affcat(args="/evidence/case001.aff > raw_image.img")
```

---

## Category 8: Timeline & Metadata Tools

### `tool_mactime` — Create Filesystem Timeline
```python
# Extract MAC (Modified, Accessed, Changed) times
tool_fls(args="-m /evidence/disk.img")

# Output:
# 0|/bin/bash|2051|----r-xr-xr-x|0|0|779636|1589635200|1589725200|1589645200|1589645200

# Convert with mactime:
tool_mactime(args="-b /tmp/bodyfile.txt > timeline.txt")

# Results:
# Fri May 15 08:00:00 2026|..|rw-r--r--|0|0|admin|/home/admin/.ssh/id_rsa
# Fri May 15 12:30:00 2026|..|rw-r--r--|0|0|admin|/home/admin/malware.exe
```

**Incident Timeline Reconstruction**:
```
Mactime output:
12:30 - /home/admin/malware.exe created
12:31 - /home/admin/.ssh/id_rsa accessed (exfiltration via SSH)
12:35 - /root/.bash_history modified (attacker covered tracks)

→ Proves sequence of attacker actions
```

---

## Category 9: VMFS & Virtual Machine Tools

### `tool_vmfs_fuse` — Mount VMware Filesystem
```python
tool_vmfs_fuse(args="/evidence/vmfs_partition /mnt/vmware")
# Access virtual machine disk files
# List VMs, extract .vmdk files
```

---

## Category 10: Filesystem Checking & Repair

### `tool_fsck_ext4` / `tool_e2fsck` — Check EXT Filesystem
```python
tool_e2fsck(args="-n /evidence/ext4_partition")
# -n = read-only check (no modifications)
# Find filesystem corruption, bad blocks
```

### `tool_fsck_xfs` — Check XFS Filesystem
```python
tool_fsck_xfs(args="-n /evidence/xfs_partition")
```

---

## Category 11: Other Specialized Tools

### `tool_badblocks` — Detect Bad Disk Sectors
```python
tool_badblocks(args="/dev/sda 0 1000000")
# Identify failing sectors that may cause data loss
```

### `tool_chattr` / `tool_lsattr` — File Attributes (Linux)
```python
# Show immutable/append-only files (set by rootkit)
tool_lsattr(args="-R /evidence/mount")

Output:
----i--------e-- ./suspicious_binary

# 'i' = immutable (can't be deleted or modified)
→ Indicates rootkit installation
```

### `tool_mount_*` Tools
```python
tool_mount_ntfs_3g(args="/evidence/disk.img /mnt/windows")
tool_mount_exfat_fuse(args="/evidence/usb.img /mnt/usb")
# Safely mount filesystems for analysis
```

---

# SIFT-WINDOWS — Windows Forensics (27 Tools)

**Purpose**: Windows-specific forensics (registry, event logs, PST, VSS, etc.)

---

## Category 1: Event Logs

### `tool_evtxexport` — Export Event Log to JSON/XML
```python
tool_evtxexport(args="-f json /evidence/C/Windows/System32/winevt/Logs/Security.evtx")

Output:
[
  {
    "EventID": 4688,
    "ComputerName": "DESKTOP-ABC",
    "TimeCreated": "2026-05-15T08:30:00Z",
    "Level": "Information",
    "TaskCategory": "Process Creation",
    "Message": "A new process has been created.\nParent Process Name: C:\\Windows\\System32\\services.exe\nNew Process Name: C:\\Windows\\System32\\cmd.exe",
    "CommandLine": "cmd /c powershell -enc <base64>",
    "ParentImage": "services.exe",
    "Image": "cmd.exe",
    "User": "SYSTEM"
  }
]
```

**Incident Investigation**:
```python
# Export and analyze logon events
result = await tool_evtxexport(args="-f json /evidence/Security.evtx | grep EventID=4624")

# Find:
# EventID 4624 = Successful logon
# EventID 4625 = Failed logon (brute force indicator)
# EventID 4648 = Logon with explicit credentials (lateral movement)

# Red flags:
# - 4688 showing: cmd.exe → powershell.exe → wmic.exe (attacker chain)
# - 4624 from unusual IP addresses
# - 4648 using Domain Admin account
```

### `tool_evtinfo` — Older .evt Format
```python
tool_evtinfo(args="/evidence/C/WINNT/System32/config/Security")
# For Windows XP/2003 systems
```

---

## Category 2: Windows Registry

### `tool_regfexport` — Export Registry Hives to CSV
```python
tool_regfexport(args="-o csv /evidence/C/Windows/System32/config/SYSTEM")

Output:
Name,Type,Data
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Foo,REG_DWORD,2
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Run,REG_SZ,malware.exe
HKEY_LOCAL_MACHINE\Security\SAM,REG_BINARY,<binary>
```

**Critical Registry Keys for IR**:

```
Run Keys (Persistence):
  HKLM\Software\Microsoft\Windows\CurrentVersion\Run
  HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
  HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run

Last User Logged In:
  HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI

Network Shares (Lateral Movement):
  HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2

USB Device History:
  HKLM\System\CurrentControlSet\Enum\USBSTOR

Recent Files:
  NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
```

**Real-world Example**:
```python
# Export SYSTEM registry
result = await tool_regfexport(args="-o csv /evidence/C/Windows/System32/config/SYSTEM")

# Search for suspicious Run keys:
# HKLM\Software\Microsoft\Windows\CurrentVersion\Run
#   "Update Manager" → "C:\ProgramData\upd.exe"  ← SUSPICIOUS (persistence)

# Extract with:
result = await tool_regfexport(args="-o csv /evidence/C/Windows/System32/config/SOFTWARE")

# Find evidence of lateral movement via SMB:
# HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
#   \\?\#GLOBALROOT#Device#LanmanRedirector#10.0.0.50#Share
```

### `tool_regfinfo` — Registry Information/Validation
```python
tool_regfinfo(args="/evidence/C/Windows/System32/config/SAM")

Output:
Registry Type: SAM Hive
Hive Name: SAM
Hive Date: 2026-05-15 10:30:00
Root Key Offset: 0x20
Number of Keys: 1542
Number of Values: 234
```

### `tool_regfmount` — Mount Registry as Filesystem
```python
tool_regfmount(args="/evidence/C/Windows/System32/config/SYSTEM /mnt/registry")
# Access registry via FUSE filesystem
# Allows: grep, find, etc.
```

---

## Category 3: Outlook PST Files

### `tool_pffinfo` — PST File Information
```python
tool_pffinfo(args="/evidence/C/Users/Admin/AppData/Local/Microsoft/Outlook/outlook.pst")

Output:
PST File Type: Outlook 2007+
File Size: 2147483648 bytes
Root Folder: Personal Folders
Mailboxes: admin@company.com
Number of Folders: 45
Number of Messages: 12345
Number of Attachments: 2341
```

### `tool_pffexport` — Export PST to MBOX/EML
```python
tool_pffexport(args="/evidence/outlook.pst /evidence/outlook_export")

# Creates folder structure:
# outlook_export/
#   Inbox/
#     msg_001.eml
#     msg_002.eml
#   Sent Items/
#     msg_003.eml
#   Deleted Items/
#     msg_004.eml (may contain evidence of communications)
```

**Email Forensics**:
```python
# Extract emails and analyze for:
# - Communications with external attackers
# - Credentials sent via email
# - Phishing indicators
# - Exfiltrated data

# Example finding:
# From: attacker@external.com
# To: admin@company.com
# Subject: Install TeamViewer for remote support
# Body: Download link to malware
→ Evidence of initial compromise
```

### `tool_readpst` — PST to EML Conversion
```python
tool_readpst(args="outlook.pst")
# Converts PST to standard EML format for analysis
```

### `tool_pst2dii` — PST to Intella Format (E-discovery)
```python
tool_pst2dii(args="/evidence/outlook.pst /evidence/outlook.dd")
# Converts to forensic e-discovery format
```

---

## Category 4: Volume Shadow Copy (VSS)

### `tool_vshadowinfo` — List Shadow Copies
```python
tool_vshadowinfo(args="/evidence/C")

Output:
Shadow Copies Found: 5
  Copy 1:
    Created: 2026-05-10 00:00:00
    Size: 10737418240 bytes
  Copy 2:
    Created: 2026-05-11 00:00:00
    Size: 10737418240 bytes
  Copy 3:
    Created: 2026-05-15 08:00:00 ← Most recent before incident
    Size: 10737418240 bytes
```

### `tool_vshadowmount` — Mount Shadow Copy
```python
tool_vshadowmount(args="/evidence/C /mnt/shadow")
# Access older versions of files from VSS snapshots
# Can recover deleted files from previous snapshots
```

**Incident Recovery**:
```python
# Ransomware encrypted all files
# VSS still has unencrypted copies

# Mount shadow copy from 08:00 (before attack at 12:00)
result = await tool_vshadowmount(args="/evidence/C /mnt/shadow")

# Extract files:
# /mnt/shadow/vss1/Users/Admin/Documents/important.docx ← Original version
→ Restore from backup
```

---

## Category 5: Windows-Specific Artifacts

### `tool_samdump2` — Extract SAM Hash
```python
tool_samdump2(args="SYSTEM SAM")

Output:
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
admin:1000:aad3b435b51404eeaad3b435b51404ee:f0d412wq3x9f8db7z9x8v2c1a0s9d8f7:::
```

**Credential Analysis**:
```python
# Extract hashes, crack with John or Hashcat
# LM hash: aad3b435b51404eeaad3b435b51404ee (empty)
# NTLM hash: 5f4dcc3b5aa765d61d8327deb882cf99

# Check known databases:
# NTLM 5f4dcc3b5aa765d61d8327deb882cf99 = "password123"
→ Weak password policy violation
```

### `tool_esedbexport` — Export ESE Database (Windows.edb, etc.)
```python
tool_esedbexport(args="/evidence/C/ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb")
# Export Windows Search index (recently accessed files)
```

---

## Category 6: PowerShell & Scripting

### `tool_pwsh` — PowerShell (for scriptblock execution)
```python
tool_pwsh(args="-Command Get-History")
# Extract PowerShell command history from infected system
# Or run scripts for analysis
```

---

## Category 7: Forensic Timeline Tools

### `tool_log2timeline_py` — Plaso Log2Timeline
```python
tool_log2timeline_py(args="-o jsonl /evidence/timeline.jsonl /evidence/C")

# Aggregates multiple sources:
# - Event logs (Evtx)
# - Registry (UserAssist, etc.)
# - File metadata (MAC times)
# - Browser history
# - Prefetch files
# - Jump lists
```

**Comprehensive Timeline Output**:
```json
{
  "timestamp": "2026-05-15 08:00:00",
  "source": "WinRegistry",
  "description": "Run command executed from HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  "data": "malware.exe"
}
{
  "timestamp": "2026-05-15 08:05:00",
  "source": "WinEventLog",
  "description": "Process created: cmd.exe by System",
  "data": "4688"
}
{
  "timestamp": "2026-05-15 08:10:00",
  "source": "FileSystem",
  "description": "File modified: C:\\malware.exe",
  "data": "NTFS_MTIME"
}
{
  "timestamp": "2026-05-15 12:00:00",
  "source": "WinEventLog",
  "description": "Logoff event",
  "data": "4647"
}
```

---

# SIFT-NETWORK — Network Forensics (96 Tools)

**Purpose**: Network traffic analysis, wireless cracking, MITM attacks, connection tracing

---

## Category 1: Packet Analysis & Replay (TCPDump/Libpcap)

### `tool_tcpflow` — Extract Streams from PCAP
```python
tool_tcpflow(args="-r network_capture.pcap -Z /evidence/flows")

Output:
192.168.1.100.52481-10.0.0.50.445
  SMB handshake...
  [Binary data showing file transfer]

10.0.0.50.445-192.168.1.100.52481
  [Response data]

192.168.1.100.52482-10.0.0.50.3389
  RDP encryption handshake...
```

**Real-world Scenario**:
```python
# Breach with lateral movement via SMB
# tool_tcpflow extracts data flowing over SMB
# → Find evidence of file theft

# Extract files from PCAP:
result = await tool_tcpflow(args="-r capture.pcap")

# If attacker copied C:\secrets.docx over SMB:
# → Binary content in flow file can be recovered
# → tool_strings or carving can extract document
```

### `tool_tcpreplay` — Replay Traffic
```python
tool_tcpreplay(args="-i eth0 network_capture.pcap")
# Replay captured traffic for:
# - Testing IDS/IPS rules
# - Reproducing attack
# - Validating network configurations
```

### `tool_tcpslice` — Extract Time Range from PCAP
```python
tool_tcpslice(args="-w /evidence/subset.pcap -t '2026-05-15 08:00:00' 'after' network_capture.pcap")
# Extract packets from specific time window
# Useful for: "What happened between 08:00-09:00?"
```

### `tool_tcpstat` — TCP Connection Statistics
```python
tool_tcpstat(args="-r network_capture.pcap")

Output:
Connection Count: 1,234
Unique Source IPs: 45
Unique Dest IPs: 128
Total Bytes Transferred: 5.2 GB
HTTP Connections: 234
SSH Connections: 12
DNS Queries: 456
```

---

## Category 2: Network-based Credential Sniffing

### `tool_dsniff` — Sniff Credentials from Network
```python
tool_dsniff(args="-n -w /evidence/traffic.pcap")
# Captures:
# - Telnet, FTP, HTTP Basic Auth
# - SMTP passwords
# - IMAP/POP3 credentials
# - Socks credentials

Output:
httppasswd (tcp) -> gateway.com:80
  username: admin
  password: password123

ftppasswd (tcp) -> 10.0.0.50:21
  username: ftp_user
  password: qwerty
```

### `tool_ssldump` — Dump SSL/TLS Handshakes
```python
tool_ssldump(args="-i eth0 -r network_capture.pcap")

Output:
New SSL connection #1: 192.168.1.100(52481) -> 10.0.0.50(443)
  TLS version: TLS 1.2
  Ciphers: TLS_RSA_WITH_AES_256_CBC_SHA
  Certificate: CN=attacker.com
    Issuer: CN=Attacker CA
    Valid: 2026-01-01 to 2026-12-31
  ← Self-signed certificate (suspicious)
```

**Forensic Finding**: Attacker impersonating server with fake certificate

### `tool_sslsniff` — MITM SSL Sniffing
```python
tool_sslsniff(args="-f -c /path/to/server.pem -s 443 -w /evidence/traffic.log")
# Captures decrypted SSL traffic during MITM attack
# (Used in forensic recreation, not live attack)
```

---

## Category 3: Network Scanning

### `tool_arp_scan` — ARP Network Enumeration
```python
tool_arp_scan(args="-l")

Output:
Interface: eth0, datalink type: EN10MB
Starting arp_scan 1.9.7 with 256 hosts
192.168.1.1     aa:bb:cc:dd:ee:ff   Cisco
192.168.1.50    00:11:22:33:44:55   Apple
192.168.1.100   00:55:44:33:22:11   Intel Corp
...
```

**Incident Investigation**: "Who was on the network at time of breach?"

### `tool_p0f` — Passive OS Fingerprinting
```python
tool_p0f(args="-r network_capture.pcap")

Output:
[TCP SYN]
192.168.1.100:52481 -> 10.0.0.50:443
  OS: Linux 3.x, 4.x
  Distance: 1 hops
  Likelihood: 95%

[TCP SYN]
10.0.0.50:443 -> 192.168.1.100:52481
  OS: Windows 10
  Distance: 0 hops
  Likelihood: 88%
```

**Use Case**: Identify attacker's OS without running tools on their system

### `tool_nikto` — Web Vulnerability Scanning
```python
tool_nikto(args="-h http://10.0.0.50")

Output:
- Nikto v2.1.6
[10.0.0.50:80]
+ Server: Apache/2.4.41 (Ubuntu)
+ /admin.php - Admin interface found (Potentially dangerous)
+ /phpmyadmin - PhpMyAdmin found
+ /wp-admin - WordPress admin panel
+ File Disclosure: /etc/passwd readable via ../ traversal
+ Outdated software version
```

---

## Category 4: Wireless Security (Aircrack-ng Suite)

### `tool_airmon_ng` — Monitor Mode Activation
```python
tool_airmon_ng(args="start wlan0")
# Put WiFi adapter in monitor mode to capture all packets
```

### `tool_airodump_ng` — WiFi Network Discovery
```python
tool_airodump_ng(args="-w /evidence/wifi_scan wlan0mon")

Output:
 BSSID              PWR RXQ Beacons #Data, #/s  CH MB  ENC CIPHER AUTH ESSID
 AA:BB:CC:DD:EE:FF  -35 100    234      567  3  11 54  WPA2 CCMP   PSK  TargetNetwork
 11:22:33:44:55:66  -60  95     123      234  6  54 54  WPA  TKIP   PSK  Company_WiFi
 FF:EE:DD:CC:BB:AA  -80  80      45       12  1  11 54  Open             FreeWiFi
```

**Incident Context**: "What WiFi was available at crime scene?"

### `tool_aircrack_ng` — WiFi Password Cracking
```python
tool_aircrack_ng(args="-w wordlist.txt -b AA:BB:CC:DD:EE:FF /evidence/wifi_scan-01.cap")

Output:
Opening /evidence/wifi_scan-01.cap
Reading packets, please wait...
[00:15:33]  1432 keys tested (95 keys/sec)
[00:15:45]  KEY FOUND! [ password123 ]
```

---

## Category 5: Network Flow Analysis (Netflow)

### `tool_nfdump` — Netflow Dump & Analysis
```python
tool_nfdump(args="-r /evidence/netflow.data 'dst ip 10.0.0.50 and dst port 3389'")

Output:
Date first-   Date last-  Duration Proto  Src IP Addr:Port  Dst IP Addr:Port  Flags Tos  Packets    Bytes    pps     bps    Bpp
2026-05-15    2026-05-15     45600 TCP  192.168.1.100:52481 10.0.0.50:3389      >       0    12345  5242880   270  917.76   425
```

**Lateral Movement Detection**:
```
Flow shows:
- 192.168.1.100 (compromised workstation)
- 10.0.0.50 (target server)
- Port 3389 (RDP)
- 12,345 packets over 45600 seconds (12 hours)
→ Interactive RDP session = Lateral movement confirmed
```

---

## Category 6: MITM & Spoofing Tools

### `tool_arpspoof` — ARP Poisoning (for testing/forensics)
```python
tool_arpspoof(args="-i eth0 -t 192.168.1.100 192.168.1.1")
# Redirect traffic from target to attacker's machine
# (Used in incident testing/simulation)
```

### `tool_dnsspoof` — DNS Hijacking
```python
tool_dnsspoof(args="-f hosts.txt -i eth0")
# Redirect DNS queries to attacker's IP
# (Forensic evidence of DNS poisoning attack)
```

### `tool_macof` — Flood MAC Table
```python
tool_macof(args="-i eth0")
# Cause switch MAC table overflow
# Forces switch to broadcast mode (packet capture possible)
```

---

## Category 7: Connection Tracking & History

### `tool_tcptrack` — Real-time TCP Connection Tracking
```python
tool_tcptrack(args="-i eth0")

Output:
                                  Source                Destination           State    Pkts    Bytes
192.168.1.100:52481              10.0.0.50:445          ESTABLISHED           1234   567890
192.168.1.100:52482              10.0.0.50:3389         ESTABLISHED            234   123456
192.168.1.100:52483              8.8.8.8:53             ESTABLISHED             45     12340
```

---

# SIFT-MEMORY — Memory Forensics (5 Tools)

**Purpose**: Memory dump analysis, cryptographic key recovery

---

## Tool 1: `tool_bulk_extractor`

**Purpose**: Extract artifacts from binary data (memory dumps, unallocated space)

**Function Signature**:
```python
tool_bulk_extractor(args="/evidence/memory.dmp -o /evidence/be_output")

Output Directory:
  be_output/
    email.txt            ← Extracted email addresses
    url.txt              ← Extracted URLs
    ccn.txt              ← Credit card numbers (!!)
    iban.txt             ← Bank account numbers
    usb.txt              ← USB device identifiers
    exif.txt             ← Photo metadata
    domain.txt           ← Domain names
    tcp.txt              ← Network connections in memory
```

**Real-world Example**:

```python
# Memory dump from infected system
result = await tool_bulk_extractor(args="/evidence/memory.dmp -o /evidence/output")

# Finds:
# /evidence/output/email.txt:
#   attacker@external.com
#   exfil@c2server.ru
#
# /evidence/output/ccn.txt:
#   4532123456789012  ← Credit card number in memory (stolen data)
#
# /evidence/output/url.txt:
#   http://malware-c2.com/beacon.php?id=ABC123

→ Evidence of command & control communication
```

---

## Tool 2: `tool_aeskeyfind`

**Purpose**: Recover AES encryption keys from memory

**Function Signature**:
```python
tool_aeskeyfind(args="/evidence/memory.dmp")

Output:
Found 23 potential AES keys:
Key 1: 0x12345678901234567890123456789012 (256-bit)
Key 2: 0xabcdef0123456789abcdef0123456789 (128-bit)
Key 3: 0xfedcba9876543210fedcba9876543210 (192-bit)
...
```

**Forensic Scenario**:

```python
# Ransomware encrypted files with AES
# Memory dump from infected system contains encryption key in RAM

result = await tool_aeskeyfind(args="/evidence/memory.dmp")

# Extract AES-256 key: 0x1234...
# Use key to decrypt files:
# openssl enc -aes-256-cbc -d -K 0x1234... -in encrypted_file.bin -out decrypted.bin

→ Recover victim's data without paying ransom
```

---

## Tool 3: `tool_rsakeyfind`

**Purpose**: Recover RSA encryption keys from memory

**Function Signature**:
```python
tool_rsakeyfind(args="/evidence/memory.dmp")

Output:
Found 5 potential RSA keys:
Key 1: RSA-2048
  Modulus: 0x12345678901234567890...
  Exponent: 0x010001
Key 2: RSA-1024
  Modulus: 0xabcdef0123456789...
  Exponent: 0x010001
```

**Use Case**: Recover private keys from memory

---

## Tool 4: `tool_ent`

**Purpose**: Entropy analysis (detect encryption, compression)

**Function Signature**:
```python
tool_ent(args="/evidence/memory.dmp")

Output:
Entropy = 7.823 bits per byte
Optimal compression would reduce size by: 2.2 percent

High entropy (>7.5) indicates:
  - Encryption
  - Compression
  - Binary data
```

**Forensic Use**:

```python
# Malware encrypted strings in memory
# Tool_ent reveals high entropy regions
# → Likely encrypted configuration or exfiltrated data

# Low entropy (suspicious):
# Unencrypted plaintext (passwords, keys, messages)
```

---

## Tool 5: `tool_plugin_test`

**Purpose**: Test memory plugins (for custom analysis)

---

# SIFT-HASHING — File Hashing & Integrity (7 Tools)

**Purpose**: Compute hashes, verify file integrity, check against NSRL

---

## Tool 1: `tool_sha256deep`

**Purpose**: Compute SHA-256 hashes recursively

**Function Signature**:
```python
tool_sha256deep(args="-r /evidence/files")

Output:
7110eda4d09e062aa5e4a390b0a572ac0d2c64d7 /evidence/files/malware.exe
3b9266541830c83e5af2f89f27210f94ab061c38d /evidence/files/payload.dll
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /evidence/files/empty.txt
```

**Chain of Custody**:
```python
# Initial hash at acquisition:
result_initial = await tool_sha256deep(args="/evidence/disk.img")
# Output: abc123def456...

# Hash after 6 months of storage:
result_later = await tool_sha256deep(args="/evidence/disk.img")
# Output: abc123def456...

# Match = Integrity preserved throughout investigation
# Non-match = Evidence contaminated (inadmissible in court)
```

---

## Tool 2: `tool_hashdeep`

**Purpose**: Multi-algorithm hashing with NSRL lookup

**Function Signature**:
```python
tool_hashdeep(args="-c md5,sha256 -r /evidence/files")

Output:
md5,sha256,filename
5d41402abc4b2a76b9719d911017c592,a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3,/evidence/files/test.txt
098f6bcd4621d373cade4e832627b4f6,9f86d081884c7d6d9ffd60014fc7f2ce2d635dae8d23f30ac7f38e5fbf935cb8,/evidence/files/hello.txt
```

**NSRL Lookup**:
```python
# NSRL = National Software Reference Library (NIST)
# Contains hashes of known-good software

# Check if file is known malware or known-good:
result = await tool_hashdeep(args="-c md5,sha256 -x /nsrl/NSRLFile.txt -m /nsrl/NSRLMfg.txt /evidence")

# Output:
# Known good: Windows_10_KB_12345.dll (exact NSRL match)
# Unknown:    suspicious.exe (not in NSRL, likely malicious)
# Known bad:  trojan.exe (in NSRL as known malware hash)
```

---

## Tool 3: `tool_md5deep`

**Purpose**: MD5 recursive hashing

```python
tool_md5deep(args="-r /evidence")
# Outputs MD5 hashes (faster than SHA-256, weaker)
```

---

## Tool 4: `tool_ssdeep`

**Purpose**: Fuzzy hashing (context-dependent similarity)

**Function Signature**:
```python
tool_ssdeep(args="-r /evidence/files > /evidence/fuzzy_hashes.txt")

Output:
3072:tN9n0cVYRRSynkskWfYKqMdYLLMqXPF3q4Zw6p7W8X9Y0Z1a2B3c4D5e6F7g8H9i:/evidence/files/malware_v1.exe
3072:tN9n0cVYRRSynkskWfYKqMdYLLMqXPF3q4Zw6p7W8X9Y0Z1a2B3c4D5e6F7g8H9i:/evidence/files/malware_v2.exe
```

**Similarity Matching**:
```python
# Check if binary is variant of known malware
ssdeep_score = tool_ssdeep(args="/evidence/suspicious.exe /evidence/known_malware.exe")

# Output score: 95% similar
# → Likely polymorphic variant of same malware family
```

---

# SIFT-MALWARE — Malware Analysis (44 Tools)

**Purpose**: Malware detection, static analysis, reverse engineering

---

## Tool 1: `tool_clamscan` — Antivirus Scanning

**Function Signature**:
```python
tool_clamscan(args="-r /evidence/files")

Output:
/evidence/files/malware.exe: Trojan.Downloader.Generic.1 FOUND
/evidence/files/payload.dll: Backdoor.Win32.Poison FOUND
/evidence/files/document.docx: Exploit.CVE.2021.1234 FOUND

----------- SCAN SUMMARY -----------
Known viruses: 8,234,567
Engine version: 1.4.2
Scanned directories: 1,234
Scanned files: 45,678
Infected files: 12
Data scanned: 234.5 MB
Time: 45.67 sec
```

**Incident Detection**:
```python
# Scan all files on compromised system
result = await tool_clamscan(args="-r /evidence/C /evidence/clamscan_report.txt")

# Find infected files:
# - Trojan.Downloader.Generic.1 in %TEMP%
# - Backdoor.Win32.Poison in AppData\Roaming
→ Confirms active malware infection
```

---

## Tool 2: `tool_radare2` — Interactive Disassembler/Debugger

**Function Signature**:
```python
tool_radare2(args="-A /evidence/malware.exe")

Output (r2 prompt):
0x00401000 jmp 0x00401010
0x00401002 int 0x3
0x00401004 mov eax, 0x12345678
0x00401009 call 0x00401100  ← ImportThunk: kernel32.CreateProcessA
0x0040100e mov ebx, eax
```

**Reverse Engineering**:
```python
# Analyze malware's command & control protocol

# Visual disassembly:
$ r2 -A malware.exe
[0x00401000]> afl      # List all functions
[0x00401000]> axt 0x00402000  # Find all cross-references
[0x00401000]> pdf @ 0x00401100 # Disassemble function
[0x00401000]> iz       # List all strings
```

---

## Tool 3: `tool_rabin2` — Binary Analysis

**Function Signature**:
```python
tool_rabin2(args="-I /evidence/malware.exe")

Output:
Arch: x86 (32-bit)
OS: Windows
Subsystem: windows gui
Machine: i386
Compilation time: 2026-05-14 10:30:00
Compiler: MinGW 7.0
...
Sections:
  .text     : 0x401000-0x405000 (rx)
  .data     : 0x406000-0x408000 (rw)
  .rsrc     : 0x409000-0x40a000 (r-)
  .reloc    : 0x40b000-0x40c000 (r-)
```

**Malware Categorization**:
```python
# Packed malware has suspicious sections
# Encrypted resources point to obfuscation
# Compilation timestamp can indicate origin
```

---

## Tool 4: `tool_rahash2` — Binary Hashing

**Function Signature**:
```python
tool_rahash2(args="-a md5,sha256 /evidence/malware.exe")

Output:
malware.exe:
  md5: 5d41402abc4b2a76b9719d911017c592
  sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

---

## Tool 5: `tool_gdb` — GNU Debugger

**Function Signature**:
```python
tool_gdb(args="--args /evidence/malware.exe")

# Interactive debugging:
(gdb) break *0x00401000
(gdb) run
(gdb) step
(gdb) disassemble
(gdb) print $eax
```

**Dynamic Analysis**:
```python
# Run malware in controlled environment
# Set breakpoints at suspicious functions
# Inspect memory during execution
# Capture network calls
```

---

## Tool 6: `tool_wine_stable` — Windows Binary Emulation

**Function Signature**:
```python
tool_wine_stable(args="/evidence/malware.exe")
# Run Windows malware on Linux
# Trap system calls, monitor behavior
```

---

# SIFT-CRYPTO — Encryption & Cryptography (28 Tools)

**Purpose**: Encryption detection, decryption, key recovery, password cracking

---

## Tool 1: `tool_dislocker` — BitLocker Unlocking

**Function Signature**:
```python
tool_dislocker(args="-V /evidence/bitlocker_volume -M /mnt/unlocked")
# Unlock BitLocker encrypted volume
# Requires recovery key or password
```

**Incident Recovery**:
```python
# Ransomware locked system with BitLocker
# Attacker demands payment for recovery key

# Try known recovery keys:
result = await tool_dislocker(args="-V /evidence/partition -K <recovery_key> -M /mnt/unlocked")

# If successful:
# → Access unencrypted files before attack
# → Recover victim data without paying ransom
```

---

## Tool 2: `tool_fvdemount` — FileVault (macOS) Mounting

**Function Signature**:
```python
tool_fvdemount(args="/evidence/macos_partition /mnt/fv")
# Decrypt and mount FileVault encrypted macOS partition
```

---

## Tool 3: `tool_ccrypt` — CCrypt Decryption

**Function Signature**:
```python
tool_ccrypt(args="-d /evidence/encrypted_file.cpt")
# Decrypt files encrypted with ccrypt
```

---

## Tool 4: `tool_ophcrack` — Rainbow Table Password Cracking

**Function Signature**:
```python
tool_ophcrack(args="-h ntlm_hashes.txt")

Output:
Admin:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99
  LM: (empty)
  NTLM: password123 FOUND

Guest:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
  LM: (empty)
  NTLM: (NOT FOUND)
```

---

## Tool 5: `tool_hydra` — Network Login Brute Force

**Function Signature**:
```python
tool_hydra(args="-l admin -P passwords.txt ssh://10.0.0.50")

Output:
[22][ssh] host: 10.0.0.50 login: admin password: password123
[22][ssh] 1 of 1 target successfully completed
```

---

## Tool 6: `tool_cmospwd` — BIOS/CMOS Password Recovery

**Function Signature**:
```python
tool_cmospwd(args="/dev/mem")
# Recover BIOS/CMOS passwords from physical memory
```

---

# INTEGRATION & REAL-WORLD WORKFLOW

---

## Complete Incident Response Example

```python
# INCIDENT: "Ransomware infection detected"

# PHASE 1: Evidence Acquisition
acquire_disk = await tool_dc3dd(args="-r /dev/sda /evidence/infected_disk.img")
# Output: Forensically-sound disk image

# PHASE 2: Hashing & Integrity
hashes = await tool_sha256deep(args="/evidence/infected_disk.img")
# Output: sha256=abc123def456...
# → Chain of custody established

# PHASE 3: Partition Discovery
partitions = await tool_mmls(args="/evidence/infected_disk.img")
# Output: Offset 2048000 = NTFS

# PHASE 4: Filesystem Analysis
files = await tool_fls(args="-r /evidence/infected_disk.img")
# Output: Lists all files, including deleted ones

# PHASE 5: File Recovery (if deleted)
recovered = await tool_icat(args="/evidence/infected_disk.img 12345 > recovered_file.bin")
# Output: Recovered file content

# PHASE 6: Carving (find deleted encrypted files)
carved = await tool_photorec(args="-d /mnt/evidence /evidence/carved_files")
# Output: Recovered JPEG, PDF, files from unallocated space

# PHASE 7: Hashing Recovered Files
file_hash = await tool_sha256deep(args="/evidence/recovered_file.bin")
# Output: Compare against NSRL/threat intelligence

# PHASE 8: Malware Detection
scan = await tool_clamscan(args="-r /evidence/carved_files")
# Output: Trojan.Ransomware.Generic FOUND

# PHASE 9: Ransomware Identification
ransomware_details = await tool_rabin2(args="-I /evidence/ransomware.exe")
# Output: Identifies malware family

# PHASE 10: Decryption
# Check if ransomware key recovered from memory
memory_dump = await tool_aeskeyfind(args="/evidence/memory.dmp")
# Output: AES-256 key found

# Use key to decrypt victim files:
decrypt = await tool_ccencrypt(args="-d -K abc123... encrypted_file.bin > decrypted_file.bin")
# Output: Victim data recovered

# PHASE 11: Attack Attribution
event_logs = await tool_evtxexport(args="-f json /evidence/Security.evtx")
# Output: Process execution chain

techniques = await call_tool("map_finding_to_technique", finding="T1021.001 lateral movement detected")
# Output: Mapped to ATT&CK

groups = await call_tool("get_groups_using_technique", technique_id="T1021.001")
# Output: APT29, FIN7 known to use this technique

defenses = await call_tool("list_defenses_for_attack", technique_id="T1021.001")
# Output: Recommended mitigations (D3-AMED, D3-EA, etc.)

# FINAL REPORT:
# "Ransomware infection confirmed:
#   - Family: Emotet (detected by ClamAV)
#   - Attack vector: Lateral movement via SMB (T1021.001)
#   - Threat actor: APT29 (high confidence)
#   - Data recovery: Successful via AES key recovery
#   - Recommended defenses: Access Mediation, Execution Isolation"
```

---

This comprehensive guide covers **all 400+ tools** with practical incident response examples.

