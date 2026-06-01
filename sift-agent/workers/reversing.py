from __future__ import annotations

import json

from mcp_client import get_tools_for_worker
from state import CaseState
from workers._base import final_text, make_finding, parse_first_json, run_react

PROMPT = (
    "You are ReversingAnalyst. For each binary candidate, use rabin2 to "
    "extract strings/imports/exports, radare2 in batch mode (r2 -A -q -c "
    "'<cmds>') to disassemble entry/main and identify control flow, "
    "rahash2 for section hashes, radiff2 for binary similarity to known "
    "families. Identify embedded URLs, decryption routines, and "
    "anti-debug tricks. Do NOT execute. "
    "Reply ONLY with a JSON object: "
    '{"findings": [{"claim": "<short>", "indicators": ["..."]}]}.'
)


async def reversing_node(state: CaseState) -> dict:
    candidates = state.get("candidate_files") or []
    refs = [e["sha256"] for e in (state.get("evidence") or []) if e.get("sha256")]
    if not candidates:
        return {}
    tools = await get_tools_for_worker("reversing")
    result = await run_react(
        name="reversing", tools=tools, prompt=PROMPT,
        task=f"Reverse statically: {json.dumps(candidates[:10])}",
        doing=f"reversing {min(len(candidates),10)} binary candidate(s)",
    )

    obj = parse_first_json(final_text(result)) or {}
    rows = obj.get("findings") if isinstance(obj, dict) else None
    findings = []
    if isinstance(rows, list):
        for r in rows:
            if not isinstance(r, dict) or not r.get("claim"):
                continue
            findings.append(make_finding(
                produced_by="reversing", claim=r["claim"],
                evidence_refs=refs, messages=result["messages"],
                confidence="probable",
            ))
    return {"findings": findings}
