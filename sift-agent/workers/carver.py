from __future__ import annotations

import json

from mcp_client import get_tools_for_worker
from state import CaseState
from workers._base import final_text, make_finding, parse_first_json, run_react

PROMPT = (
    "You are Carver. Recover deleted or unallocated artifacts from disk "
    "images. Use foremost or scalpel for signature carving, photorec for "
    "deep recovery, srch_strings for unstructured search. Focus on "
    "executables, scripts, archives, and document remnants. "
    "Reply ONLY with a JSON object: "
    '{"findings": [{"claim": "<short>", "candidate_files": ["..."]}]}.'
)


async def carver_node(state: CaseState) -> dict:
    disks = [e for e in (state.get("evidence") or []) if e.get("sha256")]
    if not disks:
        return {}
    tools = await get_tools_for_worker("carver")
    targets = [{"path": e["path"], "sha256": e["sha256"]} for e in disks]
    result = await run_react(
        name="carver", tools=tools, prompt=PROMPT,
        task=f"Carve and recover from: {json.dumps(targets)}",
        doing=f"carving {len(disks)} image(s)",
    )

    obj = parse_first_json(final_text(result)) or {}
    rows = obj.get("findings") if isinstance(obj, dict) else None
    refs = [e["sha256"] for e in disks]
    findings = []
    candidates: list[str] = []
    if isinstance(rows, list):
        for r in rows:
            if not isinstance(r, dict) or not r.get("claim"):
                continue
            findings.append(make_finding(
                produced_by="carver",
                claim=r["claim"],
                evidence_refs=refs,
                messages=result["messages"],
            ))
            for cf in r.get("candidate_files") or []:
                if isinstance(cf, str):
                    candidates.append(cf)
    return {"findings": findings, "candidate_files": candidates}
