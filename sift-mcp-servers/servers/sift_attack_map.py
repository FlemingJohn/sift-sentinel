"""
sift_attack_map.py — manual + heuristic linkage between ATT&CK and the SIFT toolset

Two structures:

  SIFT_MAPPINGS         : hand-curated for ~50 operationally common techniques.
                          Maps an ATT&CK technique ID to specific SIFT binaries
                          plus a one-line forensic_note.

  DATA_SOURCE_TO_SERVER : fallback heuristic. Maps an ATT&CK data_source name
                          (e.g. "Windows Registry") to the SIFT server most
                          likely to surface evidence (e.g. "sift-windows").

When sift_attack.get_sift_tools_for_technique(tid) runs, it first checks
SIFT_MAPPINGS for a direct hit; if none, it walks the 4-hop graph
(technique → detection-strategy → analytic → data-component → data-source)
and converts each data_source name via DATA_SOURCE_TO_SERVER.
"""

SIFT_MAPPINGS: dict[str, dict] = {

    # ── Execution ────────────────────────────────────────────────────────────
    "T1059": {
        "tools": [
            ("sift-windows", "evtxexport", "Microsoft-Windows-PowerShell/Operational + cmd.exe Process Creation 4688 in Security.evtx"),
            ("sift-disk",    "fls",        "Locate interpreter executables (powershell.exe, cmd.exe, wscript.exe, bash) in MFT/timeline"),
            ("sift-windows", "log2timeline.py", "Pull all shell-history artifacts (ConsoleHost_history.txt, .bash_history) into a unified plaso timeline"),
            ("sift-memory",  "bulk_extractor", "Extract command-line strings from RAM via scan_strings / scan_winpe"),
        ],
        "forensic_note": "Command/script interpreters are the #1 living-off-the-land surface. Look for ScriptBlock logging (EID 4103/4104) and parent-child process anomalies in 4688.",
    },
    "T1059.001": {
        "tools": [
            ("sift-windows", "evtxexport", "PowerShell EID 4103 (module logging) and 4104 (script block) capture full command text incl. obfuscation"),
            ("sift-disk",    "fls",        "ConsoleHost_history.txt and pwsh history under %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\"),
            ("sift-memory",  "bulk_extractor", "Carve PS scriptblocks (often deobfuscated) from memory"),
            ("sift-windows", "regfinfo",   "Check HKLM\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine for engine state"),
        ],
        "forensic_note": "PowerShell is the dominant fileless-execution vector. EID 4104 captures the deobfuscated script content even when the attacker used FromBase64String + IEX.",
    },
    "T1059.003": {
        "tools": [
            ("sift-windows", "evtxexport", "Security.evtx EID 4688 with ProcessName=cmd.exe and CommandLine field populated"),
            ("sift-windows", "log2timeline.py", "AppCompatCache, ShimCache, BAM/DAM for cmd.exe execution history"),
            ("sift-disk",    "fls",        "Locate batch files (.bat/.cmd) and AppCompatCache hive entries"),
        ],
        "forensic_note": "cmd.exe is often a child of office apps or web shells. Parent-PID + command-line in 4688 is the smoking gun.",
    },
    "T1059.004": {
        "tools": [
            ("sift-disk",    "fls",        "Locate .bash_history, .zsh_history, /root/.history, sudoers.d/"),
            ("sift-windows", "log2timeline.py", "Linux audit.log + auth.log shell session reconstruction"),
            ("sift-memory",  "bulk_extractor", "Carve bash command strings from RAM"),
        ],
        "forensic_note": "Bash history is often cleared but the inode may persist; check filesystem journal and unallocated space.",
    },
    "T1053": {
        "tools": [
            ("sift-windows", "evtxexport", "Microsoft-Windows-TaskScheduler/Operational EID 106 (task registered), 140, 141, 200, 201"),
            ("sift-windows", "regfinfo",   "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks"),
            ("sift-disk",    "fls",        "Files under C:\\Windows\\System32\\Tasks\\ (XML scheduled task definitions)"),
        ],
        "forensic_note": "Scheduled tasks are a top persistence and lateral-movement technique. The XML files in System32\\Tasks contain the full command and trigger.",
    },
    "T1053.005": {
        "tools": [
            ("sift-windows", "evtxexport", "Microsoft-Windows-TaskScheduler/Operational EID 106/200/201"),
            ("sift-windows", "regfinfo",   "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache"),
        ],
        "forensic_note": "Windows-specific scheduled task. EID 106 captures task name + user; the TaskCache hive captures the full XML.",
    },

    # ── Persistence ──────────────────────────────────────────────────────────
    "T1547": {
        "tools": [
            ("sift-windows", "regfinfo",   "HKLM/HKCU \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run, RunOnce, Winlogon, Image File Execution Options"),
            ("sift-disk",    "fls",        "Files under Startup folders (per-user and ALLUSERSPROFILE)"),
            ("sift-windows", "log2timeline.py", "Registry-aware timeline catches autostart registrations across all known keys"),
        ],
        "forensic_note": "Autostart Extension Points (ASEPs) are the most common Windows persistence. Run/RunOnce + Image File Execution Options cover ~80% of cases.",
    },
    "T1547.001": {
        "tools": [
            ("sift-windows", "regfinfo",   "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run, RunOnce, RunServices, RunServicesOnce"),
            ("sift-windows", "regfexport", "Export Run key contents with timestamps for timeline"),
        ],
        "forensic_note": "Registry Run keys are the textbook persistence. Both HKLM (system-wide) and HKCU (per-user) need checking.",
    },
    "T1543": {
        "tools": [
            ("sift-windows", "evtxexport", "System.evtx EID 7045 (service install), 7036 (service state)"),
            ("sift-windows", "regfinfo",   "HKLM\\SYSTEM\\CurrentControlSet\\Services\\ — ImagePath, ServiceDll, Start type"),
            ("sift-disk",    "fls",        "Locate service binaries via ImagePath; check for unsigned or relocated binaries"),
        ],
        "forensic_note": "Service-based persistence survives reboots and often runs as SYSTEM. EID 7045 is the canonical detection.",
    },
    "T1543.003": {
        "tools": [
            ("sift-windows", "evtxexport", "System.evtx EID 7045 + 4697 (service install) and 7036 (state change)"),
            ("sift-windows", "regfinfo",   "HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>"),
        ],
        "forensic_note": "Windows-service persistence. ImagePath, ServiceDll, and Start=2 (auto) are the fields attackers tamper with.",
    },
    "T1136": {
        "tools": [
            ("sift-windows", "evtxexport", "Security.evtx EID 4720 (account created), 4732 (added to local group), 4728 (added to global group)"),
            ("sift-windows", "samdump2",   "Dump SAM hive to enumerate accounts present at acquisition time"),
            ("sift-windows", "regfinfo",   "HKLM\\SAM\\SAM\\Domains\\Account\\Users\\ — RID list and account flags"),
        ],
        "forensic_note": "Account creation is high-noise but EID 4720 with privileged group adds is a strong signal of post-exploit consolidation.",
    },
    "T1574": {
        "tools": [
            ("sift-windows", "regfinfo",   "HKLM\\SYSTEM\\...\\Services\\<svc>\\Parameters\\ServiceDll, KnownDLLs, search-order paths"),
            ("sift-disk",    "fls",        "Look for DLLs in app dirs that shadow system DLLs (DLL search-order hijack)"),
            ("sift-malware", "pescan",     "PE inspection on suspicious DLLs to detect unsigned or recently compiled binaries"),
        ],
        "forensic_note": "Hijack Execution Flow (DLL search order, COM hijack, .lnk path interception) is subtle. Comparing on-disk DLL hashes against known-good is the best detector.",
    },

    # ── Privilege Escalation / Defense Evasion ───────────────────────────────
    "T1055": {
        "tools": [
            ("sift-memory",  "bulk_extractor", "Scan RAM for injected code regions (RWX pages, hollowed PE headers)"),
            ("sift-malware", "radare2",    "Disassemble dumped process memory to identify shellcode / injected DLL"),
            ("sift-malware", "pescan",     "Detect anomalies in dumped PE images (entropy spikes, mismatched section permissions)"),
            ("sift-windows", "evtxexport", "Sysmon EID 8 (CreateRemoteThread), 10 (ProcessAccess)"),
        ],
        "forensic_note": "Process injection requires memory forensics to confirm — disk artifacts are weak. Sysmon 8/10 are the realtime signals, RAM carving is the post-mortem evidence.",
    },
    "T1027": {
        "tools": [
            ("sift-memory",  "ent",        "Compute entropy of suspicious files; >7.5 strongly suggests packing or encryption"),
            ("sift-malware", "upx-ucl",    "Attempt UPX unpacking; success means commodity packer"),
            ("sift-malware", "pescan",     "Detect PE anomalies — encoded sections, unusual imports, anti-disassembly"),
            ("sift-malware", "radare2",    "Static analysis on suspicious binaries; rabin2 -I to list packer signatures"),
        ],
        "forensic_note": "Obfuscation is everywhere in modern malware. High entropy + small import table + sus section names = packed/encrypted payload.",
    },
    "T1112": {
        "tools": [
            ("sift-windows", "regfinfo",   "Diff hives against known-good baseline; check NTUSER.DAT and SYSTEM/SOFTWARE timestamps"),
            ("sift-windows", "regfexport", "Export full key trees for timeline correlation"),
            ("sift-windows", "evtxexport", "Microsoft-Windows-Sysmon/Operational EID 12/13/14 (registry value set)"),
        ],
        "forensic_note": "Registry modification is the Swiss-army knife of defense evasion. Plaso's regripper-style timeline catches most additions; deletions require unallocated-space carving.",
    },
    "T1070": {
        "tools": [
            ("sift-disk",    "tsk_recover", "Recover deleted files from unallocated space via Sleuthkit"),
            ("sift-disk",    "extundelete", "ext3/ext4-specific deleted-file recovery"),
            ("sift-disk",    "scalpel",    "Header/footer-based carving for known file types"),
            ("sift-disk",    "foremost",   "Generic file carving across raw disk image"),
            ("sift-windows", "log2timeline.py", "Reconstruct deleted activity via journals (USN, $LogFile, Prefetch) even after explicit deletion"),
        ],
        "forensic_note": "Indicator removal is when forensic carving pays off. Even after 'sdelete' the MFT entry and journal often survive.",
    },
    "T1070.004": {
        "tools": [
            ("sift-disk",    "fls",        "MFT analysis — deleted entries are flagged but recoverable"),
            ("sift-disk",    "tsk_recover", "Bulk-recover deleted files preserving directory structure"),
            ("sift-disk",    "extundelete", "ext3/4 file undeletion via journal replay"),
        ],
        "forensic_note": "File deletion only marks the MFT record as free. Until the clusters are overwritten, fls/icat can read the content.",
    },

    # ── Credential Access ────────────────────────────────────────────────────
    "T1003": {
        "tools": [
            ("sift-windows", "samdump2",   "Dump NTLM hashes from offline SAM hive"),
            ("sift-memory",  "bulk_extractor", "Scan memory image for password material — scan_aes, scan_winpe"),
            ("sift-memory",  "aeskeyfind", "Find AES keys (used by LSASS, Mimikatz state) in RAM"),
            ("sift-windows", "evtxexport", "Security.evtx EID 4624 (logon) 4672 (special privileges); Sysmon 10 (lsass access)"),
        ],
        "forensic_note": "Credential dumping requires correlating disk artifacts (SAM, NTDS) with memory (LSASS region). Memory is the only place plaintext appears.",
    },
    "T1003.001": {
        "tools": [
            ("sift-memory",  "aeskeyfind", "Locate AES keys used to encrypt LSASS-resident credentials"),
            ("sift-memory",  "bulk_extractor", "Scan RAM image for NTLM/Kerberos artifacts"),
            ("sift-windows", "evtxexport", "Sysmon EID 10 with TargetImage=lsass.exe is the strongest live signal"),
        ],
        "forensic_note": "LSASS dumping (Mimikatz, ProcDump, comsvcs.dll) is the dominant cred-theft path. Memory forensics is mandatory — disk shows nothing meaningful.",
    },
    "T1003.002": {
        "tools": [
            ("sift-windows", "samdump2",   "Dump LM/NTLM hashes directly from SAM hive offline"),
            ("sift-windows", "regfinfo",   "Inspect SAM hive metadata for tampering"),
            ("sift-disk",    "fls",        "Locate SAM hive copies that attackers staged (often in %TEMP%)"),
        ],
        "forensic_note": "SAM hive offline dump bypasses LSASS protections. Look for copies of \\Windows\\System32\\config\\SAM in unusual locations.",
    },
    "T1003.003": {
        "tools": [
            ("sift-disk",    "fls",        "Locate NTDS.dit copies (often staged in %TEMP% or admin profiles after ntdsutil)"),
            ("sift-windows", "evtxexport", "Microsoft-Windows-NTDS/Audit and Directory Service events"),
            ("sift-windows", "log2timeline.py", "VSS snapshots may contain NTDS.dit from DCSync precursor"),
        ],
        "forensic_note": "NTDS.dit theft is a domain-takeover signal. Volume Shadow Copy is the textbook extraction method; check VSS event log.",
    },
    "T1110": {
        "tools": [
            ("sift-windows", "evtxexport", "Security.evtx EID 4625 (failed logon) clusters; 4740 (account locked out)"),
            ("sift-network", "ngrep",      "Network capture — repeated auth attempts to AD/SMB/RDP from single source"),
            ("sift-crypto",  "hydra",      "Validate that credentials in question are actually brute-forceable"),
        ],
        "forensic_note": "Failed-logon clusters with >5 attempts to one account from one source IP, then a single success, is the classic brute-force signature.",
    },

    # ── Discovery ────────────────────────────────────────────────────────────
    "T1083": {
        "tools": [
            ("sift-windows", "evtxexport", "Sysmon EID 1 + command line containing dir, ls, tree, Get-ChildItem"),
            ("sift-windows", "log2timeline.py", "Prefetch (.pf) shows recently executed enumerators (cmd.exe with arguments visible in Win10+ Prefetch)"),
            ("sift-disk",    "fls",        "Examine Prefetch and AppCompatCache for enumeration tools"),
        ],
        "forensic_note": "File discovery is high-volume but the pattern (single user enumerating shared drives within minutes of logon) is distinctive.",
    },
    "T1057": {
        "tools": [
            ("sift-memory",  "bulk_extractor", "Carve process command lines from RAM"),
            ("sift-windows", "evtxexport", "Sysmon EID 1 with command line tasklist, ps, Get-Process"),
        ],
        "forensic_note": "Process enumeration usually precedes injection or impersonation. Correlate with subsequent EID 8/10.",
    },
    "T1018": {
        "tools": [
            ("sift-network", "arp-scan",   "Detect ARP-scan activity in pcap; high request rate from one host"),
            ("sift-network", "nbtscan",    "Identify NetBIOS broadcast scans in capture"),
            ("sift-windows", "evtxexport", "Security.evtx EID 5145 (network share access) burst from one source"),
        ],
        "forensic_note": "Remote-system discovery via ARP, NetBIOS, or SMB enumeration leaves loud network signatures even when host logs are wiped.",
    },

    # ── Lateral Movement ─────────────────────────────────────────────────────
    "T1021": {
        "tools": [
            ("sift-windows", "evtxexport", "Security.evtx EID 4624 type 3 (network), type 10 (remote interactive)"),
            ("sift-network", "tshark",     "Pcap analysis for RDP (3389), SMB (445), WinRM (5985/5986), SSH (22)"),
            ("sift-windows", "log2timeline.py", "RDP cache files, ShellBags, and Jump Lists show lateral targets visited"),
        ],
        "forensic_note": "Lateral movement is the high-value detection point. Type 3/10 logons from internal hosts at unusual times = pivot candidate.",
    },
    "T1021.001": {
        "tools": [
            ("sift-windows", "evtxexport", "Security.evtx EID 4624 LogonType=10; Microsoft-Windows-TerminalServices-* operational logs"),
            ("sift-disk",    "fls",        "RDP bitmap cache (.bmc) and connection cache (default.rdp) under user profile"),
            ("sift-network", "tshark",     "TCP 3389 sessions; check for unusual source IPs / certificates"),
        ],
        "forensic_note": "RDP is the most common Windows pivot. The bitmap cache reconstructs visual evidence of what the attacker saw on the screen.",
    },
    "T1021.002": {
        "tools": [
            ("sift-windows", "evtxexport", "Security.evtx EID 4624 type 3 + 5145 (named pipe access — IPC$, ADMIN$)"),
            ("sift-network", "tshark",     "Pcap with smb2 protocol; check for tree-connect to ADMIN$, C$"),
            ("sift-network", "smbinfo",    "Inspect SMB shares accessed during the relevant window"),
        ],
        "forensic_note": "SMB lateral movement (psexec-style) leaves Service Control Manager events 7045 on the target alongside the type-3 logon.",
    },

    # ── Command and Control ──────────────────────────────────────────────────
    "T1071": {
        "tools": [
            ("sift-network", "tshark",     "Pcap analysis — flag long-lived connections to single foreign endpoint"),
            ("sift-network", "ngrep",      "Content-search pcap for protocol patterns / known C2 strings"),
            ("sift-network", "p0f",        "Passive OS fingerprinting of remote endpoints"),
        ],
        "forensic_note": "C2 traffic hides in plain-protocol noise. Look at session duration, bytes ratio (upload/download), and DNS request patterns.",
    },
    "T1071.001": {
        "tools": [
            ("sift-network", "tshark",     "Filter http.host and http.user_agent; cluster on unusual UAs and rare hosts"),
            ("sift-network", "ngrep",      "Inspect raw HTTP payloads for beacon-style patterns"),
            ("sift-network", "nfdump",     "Netflow analysis — beaconing shows as periodic small connections"),
        ],
        "forensic_note": "HTTPS C2 is the modern default. Without TLS decryption, focus on SNI/JA3 patterns + connection cadence.",
    },
    "T1105": {
        "tools": [
            ("sift-network", "tshark",     "Identify large file transfers in pcap (smb-write, http-post)"),
            ("sift-disk",    "fls",        "Recently dropped executables in %TEMP%, Public Downloads"),
            ("sift-disk",    "foremost",   "Carve recently-allocated binaries from disk slack/unalloc"),
        ],
        "forensic_note": "Tool ingress is where staged binaries land. Correlate network download with on-disk creation time within seconds.",
    },

    # ── Exfiltration ─────────────────────────────────────────────────────────
    "T1041": {
        "tools": [
            ("sift-network", "nfdump",     "Netflow record review — high outbound byte counts to single destination"),
            ("sift-network", "tshark",     "Identify staging archives (.7z, .rar, .zip) in HTTP/SMB upload traffic"),
        ],
        "forensic_note": "C2-channel exfil is volume-detectable. Plot bytes-out per destination over time; spikes outside business hours are the signal.",
    },

    # ── Impact ───────────────────────────────────────────────────────────────
    "T1486": {
        "tools": [
            ("sift-disk",    "fls",        "MFT analysis — mass file rename/modification with sequential timestamps"),
            ("sift-memory",  "ent",        "Encrypted files have ~8.0 entropy; pre-ransom files have varied entropy"),
            ("sift-malware", "clamscan",   "AV signature scan to identify known ransomware families"),
            ("sift-disk",    "tsk_recover", "Recover pre-encryption shadow copies if not deleted"),
            ("sift-windows", "evtxexport", "Microsoft-Windows-VolumeSnapshotShim/Operational + System.evtx vssadmin events"),
        ],
        "forensic_note": "Ransomware leaves a distinctive timeline: shadow copies deleted (T1490), then sequential mass-file modification with rising entropy. The order matters.",
    },
    "T1490": {
        "tools": [
            ("sift-windows", "evtxexport", "Application.evtx + System.evtx for VSS deletion (Event Source: VSS, 8224), wbadmin, bcdedit events"),
            ("sift-windows", "log2timeline.py", "Captures vssadmin delete shadows / wmic shadowcopy delete command-line execution"),
        ],
        "forensic_note": "Pre-ransom recovery sabotage. 'vssadmin delete shadows' followed by mass file modification within minutes = ransomware playbook.",
    },
    "T1485": {
        "tools": [
            ("sift-disk",    "tsk_recover", "Bulk-recover deleted files"),
            ("sift-disk",    "extundelete", "ext-specific recovery"),
            ("sift-disk",    "foremost",   "Carve from disk slack"),
            ("sift-disk",    "scalpel",    "Header/footer carving with custom signatures"),
        ],
        "forensic_note": "Data destruction is recoverable until clusters are overwritten. Imaging the disk read-only ASAP is the priority.",
    },

    # ── Initial Access ───────────────────────────────────────────────────────
    "T1078": {
        "tools": [
            ("sift-windows", "evtxexport", "Security.evtx EID 4624 — logon type, source IP, account; cluster on unusual src+dst pairs"),
            ("sift-windows", "log2timeline.py", "Builds full logon timeline including failed → successful patterns"),
        ],
        "forensic_note": "Valid Accounts is the #1 initial access vector. Look for first-time-seen account-source pairs and off-hours logons.",
    },
    "T1190": {
        "tools": [
            ("sift-network", "tshark",     "Pcap analysis for exploit patterns (SQLi, deserialization, path traversal)"),
            ("sift-network", "nikto",      "Vulnerability scanner output as triage for which services were targeted"),
            ("sift-disk",    "fls",        "Web shell artifacts in webroot — recently created .aspx/.php/.jsp"),
        ],
        "forensic_note": "Public-facing app exploits often drop a web shell. Correlate web access logs with on-disk file creation in document root within seconds.",
    },
    "T1133": {
        "tools": [
            ("sift-windows", "evtxexport", "Microsoft-Windows-TerminalServices-LocalSessionManager EID 21/24 (RDP); VPN client logs"),
            ("sift-network", "nfdump",     "External-source flows to RDP/VPN/SSH/Citrix endpoints"),
        ],
        "forensic_note": "External services (RDP, VPN, Citrix) are the easy initial-access targets. First-time-seen source country/ASN is a strong signal.",
    },
}


DATA_SOURCE_TO_SERVER: dict[str, str | None] = {
    # ── v16 ATT&CK data-component names (canonical heuristic keys) ───────────
    "Process Creation":               "sift-windows",
    "Process Termination":            "sift-windows",
    "Process Metadata":               "sift-windows",
    "Process Access":                 "sift-malware",
    "Command Execution":              "sift-windows",
    "Script Execution":               "sift-windows",
    "Module Load":                    "sift-malware",
    "Driver Load":                    "sift-windows",
    "File Creation":                  "sift-disk",
    "File Modification":              "sift-disk",
    "File Deletion":                  "sift-disk",
    "File Access":                    "sift-disk",
    "File Metadata":                  "sift-disk",
    "Drive Modification":             "sift-disk",
    "Drive Access":                   "sift-disk",
    "Drive Creation":                 "sift-disk",
    "Image Creation":                 "sift-disk",
    "Image Modification":             "sift-disk",
    "Image Deletion":                 "sift-disk",
    "Volume Creation":                "sift-disk",
    "Volume Modification":            "sift-disk",
    "Volume Deletion":                "sift-disk",
    "Volume Metadata":                "sift-disk",
    "Snapshot Creation":              "sift-disk",
    "Snapshot Modification":          "sift-disk",
    "Snapshot Deletion":              "sift-disk",
    "Snapshot Metadata":              "sift-disk",
    "Windows Registry Key Creation":  "sift-windows",
    "Windows Registry Key Modification": "sift-windows",
    "Windows Registry Key Deletion":  "sift-windows",
    "Windows Registry Key Access":    "sift-windows",
    "Logon Session Creation":         "sift-windows",
    "Logon Session Metadata":         "sift-windows",
    "User Account Creation":          "sift-windows",
    "User Account Modification":      "sift-windows",
    "User Account Deletion":          "sift-windows",
    "User Account Authentication":    "sift-windows",
    "Group Modification":             "sift-windows",
    "Active Directory Object Creation":     "sift-windows",
    "Active Directory Object Modification": "sift-windows",
    "Active Directory Object Deletion":     "sift-windows",
    "Active Directory Object Access":       "sift-windows",
    "Active Directory Credential Request":  "sift-windows",
    "Service Creation":               "sift-windows",
    "Service Modification":           "sift-windows",
    "Service Metadata":               "sift-windows",
    "Scheduled Job Creation":         "sift-windows",
    "Scheduled Job Modification":     "sift-windows",
    "Scheduled Job Metadata":         "sift-windows",
    "Scheduled Job Execution":        "sift-windows",
    "WMI Creation":                   "sift-windows",
    "Network Traffic Flow":           "sift-network",
    "Network Traffic Content":        "sift-network",
    "Network Connection Creation":    "sift-network",
    "Network Share Access":           "sift-network",
    "Domain Name Resolution":         "sift-network",
    "Domain Name Active":             "sift-network",
    "Domain Name Passive":            "sift-network",
    "Firewall Rule Modification":     "sift-network",
    "Application Log Content":        "sift-windows",
    "Cloud Service Modification":     None,
    "Cloud Service Enumeration":      None,
    "Cloud Service Disable":          None,
    "Cloud Service Metadata":         None,
    "Cloud Storage Access":           None,
    "Cloud Storage Modification":     None,
    "Container Creation":             None,
    "Container Start":                None,
    "Container Enumeration":          None,
    "Pod Creation":                   None,
    "Pod Modification":               None,
    "Pod Enumeration":                None,
    "Persona Creation":               None,
    "Persona Modification":           None,
    "Instance Creation":              None,
    "Instance Modification":          None,
    "Instance Start":                 None,
    "Instance Stop":                  None,
    "Instance Termination":           None,
    "Instance Metadata":              None,
    "Internet Scan: Response Content":     None,
    "Internet Scan: Response Metadata":    None,
    "Firmware Modification":          "sift-disk",

    # ── legacy data-source names (pre-v16, still in ICS/Mobile bundles) ──────
    # Windows-side data sources → sift-windows (registry, evtx, logon)
    "Windows Registry":            "sift-windows",
    "Active Directory":            "sift-windows",
    "User Account":                "sift-windows",
    "Group":                       "sift-windows",
    "Logon Session":               "sift-windows",
    "Service":                     "sift-windows",
    "Scheduled Job":               "sift-windows",
    "Application Log":             "sift-windows",
    "Windows Management Instrumentation": "sift-windows",
    "Script":                      "sift-windows",
    "Process":                     "sift-windows",
    "Command":                     "sift-windows",
    "Driver":                      "sift-windows",
    "WMI":                         "sift-windows",
    "Authentication":              "sift-windows",
    "Cloud Service":               None,
    "Cloud Storage":               None,
    "Container":                   None,
    "Web Credential":              None,
    "Persona":                     None,
    "Internet Scan":               None,
    "Pod":                         None,
    "Instance":                    None,
    "Image":                       "sift-disk",

    # Disk / filesystem
    "File":                        "sift-disk",
    "Drive":                       "sift-disk",
    "Volume":                      "sift-disk",
    "Snapshot":                    "sift-disk",
    "Firmware":                    "sift-disk",
    "Sensor Health":               "sift-disk",

    # Memory / loaded modules
    "Memory Drive":                "sift-memory",
    "Module":                      "sift-malware",
    "Image Loaded":                "sift-malware",

    # Network
    "Network Traffic":             "sift-network",
    "Network Connection Creation": "sift-network",
    "Network Share":               "sift-network",
    "Domain Name":                 "sift-network",
}
