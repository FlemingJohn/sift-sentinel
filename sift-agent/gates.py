from __future__ import annotations

from typing import Literal

from console_logger import log
from state import CaseState


def gate_hash_ok(state: CaseState) -> Literal["ok", "fail"]:
    evidence = state.get("evidence") or []
    if not evidence:
        log.gate("hash_ok", "fail")
        return "fail"
    ok = all(e.get("sha256") for e in evidence)
    decision: Literal["ok", "fail"] = "ok" if ok else "fail"
    log.gate("hash_ok", decision)
    return decision


def gate_attribution_ok(state: CaseState) -> Literal["ok", "fail"]:
    findings = state.get("findings") or []
    if not findings:
        log.gate("attribution_ok", "fail")
        return "fail"
    ok = all(f.get("attack_techniques") for f in findings)
    decision: Literal["ok", "fail"] = "ok" if ok else "fail"
    log.gate("attribution_ok", decision)
    return decision


def halt_handler(state: CaseState) -> dict:
    if state.get("halt_reason"):
        reason = state["halt_reason"]
    elif not (state.get("evidence") or []):
        reason = "no_evidence"
    elif not all(e.get("sha256") for e in state.get("evidence", [])):
        reason = "unhashed_evidence"
    elif not all(f.get("attack_techniques") for f in state.get("findings", [])):
        reason = "missing_attack_attribution"
    else:
        reason = "unknown"
    log.error("halt", f"reason={reason}")
    return {"phase": "halted", "halted": True, "halt_reason": reason}
