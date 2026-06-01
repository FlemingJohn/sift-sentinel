from __future__ import annotations

from typing import Annotated, Literal, TypedDict

from langgraph.graph.message import add_messages


class ChainEntry(TypedDict):
    ts: str
    actor: str
    tool: str
    envelope_sha256: str


class Evidence(TypedDict, total=False):
    path: str
    sha256: str | None
    ssdeep: str | None
    md5: str | None
    size_bytes: int | None
    mime: str | None
    acquired_by: str | None
    chain_of_custody: list[ChainEntry]


class Finding(TypedDict, total=False):
    id: str
    claim: str
    evidence_refs: list[str]
    tool_output_hash: str
    confidence: Literal["confirmed", "probable", "weak"]
    attack_techniques: list[str]
    d3fend_defenses: list[str]
    produced_by: str


class WorkerError(TypedDict, total=False):
    ts: str
    worker: str
    tool: str | None
    exit_code: int | None
    message: str


Phase = Literal[
    "acquire", "verify", "analyze", "attribute", "defend", "report", "halted", "done"
]


def merge_evidence(left: list, right: list) -> list:
    by_path: dict = {}
    for e in (left or []):
        if not isinstance(e, dict) or "path" not in e:
            continue
        by_path[e["path"]] = dict(e)
    for e in (right or []):
        if not isinstance(e, dict) or "path" not in e:
            continue
        if e["path"] in by_path:
            merged = {**by_path[e["path"]], **{k: v for k, v in e.items() if v is not None}}
            old_chain = by_path[e["path"]].get("chain_of_custody") or []
            new_chain = e.get("chain_of_custody") or []
            if new_chain and new_chain is not old_chain:
                merged["chain_of_custody"] = old_chain + [
                    c for c in new_chain if c not in old_chain
                ]
            by_path[e["path"]] = merged
        else:
            by_path[e["path"]] = dict(e)
    return list(by_path.values())


def merge_findings(left: list, right: list) -> list:
    by_id: dict = {}
    for f in (left or []):
        if not isinstance(f, dict) or "id" not in f:
            continue
        by_id[f["id"]] = dict(f)
    for f in (right or []):
        if not isinstance(f, dict) or "id" not in f:
            continue
        if f["id"] in by_id:
            cur = by_id[f["id"]]
            patch = {k: v for k, v in f.items() if v is not None}
            for list_field in ("attack_techniques", "d3fend_defenses", "evidence_refs"):
                if list_field in patch:
                    cur_list = cur.get(list_field) or []
                    new_list = patch[list_field] or []
                    patch[list_field] = list({*cur_list, *new_list})
            cur.update(patch)
        else:
            by_id[f["id"]] = dict(f)
    return list(by_id.values())


def extend_list(left: list, right: list) -> list:
    return (left or []) + (right or [])


class CaseState(TypedDict, total=False):
    case_id: str
    messages: Annotated[list, add_messages]
    phase: Phase

    evidence: Annotated[list[Evidence], merge_evidence]
    findings: Annotated[list[Finding], merge_findings]
    errors: Annotated[list[WorkerError], extend_list]

    halted: bool
    halt_reason: str | None

    has_disk_image: bool
    has_memory_dump: bool
    has_pcap: bool
    has_windows_evt: bool
    has_pe_candidates: bool
    has_encrypted_volume: bool
    candidate_files: Annotated[list[str], extend_list]


WRITE_AUTHORITY: dict[str, set[str]] = {
    "acquirer":        {"evidence", "has_disk_image", "has_memory_dump", "has_pcap"},
    "hasher":          {"evidence"},
    "filesystem":      {"findings", "candidate_files"},
    "carver":          {"findings", "candidate_files"},
    "windows":         {"findings", "has_windows_evt"},
    "memory":          {"findings"},
    "network":         {"findings"},
    "malware_static":  {"findings", "has_pe_candidates"},
    "reversing":       {"findings"},
    "crypto":          {"findings", "has_encrypted_volume"},
    "attack_map":      {"findings"},
    "defense_map":     {"findings"},
    "synthesizer":     set(),
    "supervisor":      {"phase"},
    "gate":            {"phase", "halted", "halt_reason"},
}
