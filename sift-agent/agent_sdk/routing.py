ANALYSIS_SPECIALISTS = [
    "filesystem", "carver", "windows", "memory",
    "network", "malware_static", "reversing", "crypto",
]


def select_specialists(case_state):
    selected = []
    if case_state.has_disk_image:
        selected.append("filesystem")
        selected.append("carver")
    if case_state.has_windows_event_logs:
        selected.append("windows")
    if case_state.has_memory_dump:
        selected.append("memory")
    if case_state.has_pcap:
        selected.append("network")
    if case_state.has_portable_executable_candidates or case_state.candidate_files:
        selected.append("malware_static")
        selected.append("reversing")
    if case_state.has_encrypted_volume:
        selected.append("crypto")
    if not selected:
        selected.append("filesystem")
    ordered = []
    for specialist_name in selected:
        if specialist_name not in ordered:
            ordered.append(specialist_name)
    return ordered
