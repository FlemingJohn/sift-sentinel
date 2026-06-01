from __future__ import annotations

from state import CaseState

SPECIALISTS = [
    "filesystem", "carve", "windows", "memory",
    "network", "malware_static", "reversing", "crypto",
]


def pick_specialists(state: CaseState) -> list[str]:
    needs: list[str] = []
    if state.get("has_disk_image"):
        needs += ["filesystem", "carve"]
    if state.get("has_windows_evt"):
        needs.append("windows")
    if state.get("has_memory_dump"):
        needs.append("memory")
    if state.get("has_pcap"):
        needs.append("network")
    if state.get("has_pe_candidates") or state.get("candidate_files"):
        needs += ["malware_static", "reversing"]
    if state.get("has_encrypted_volume"):
        needs.append("crypto")
    if not needs:
        needs = ["filesystem"]
    seen, ordered = set(), []
    for n in needs:
        if n not in seen:
            ordered.append(n)
            seen.add(n)
    return ordered


def analysis_router(state: CaseState) -> dict:
    return {"phase": "analyze"}
