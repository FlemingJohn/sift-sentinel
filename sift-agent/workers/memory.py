from __future__ import annotations

import json

from mcp_client import get_tools_for_worker
from state import CaseState
from workers._base import final_text, make_finding, parse_first_json, run_react

PROMPT = (
    "You are MemoryAnalyst. Analyse memory dumps. Run bulk_extractor to "
    "extract IPs, URLs, emails, credit cards, BASE64 blobs. Use aeskeyfind "
    "and rsakeyfind to locate keys in pageable memory. Use ent to measure "
    "entropy of suspicious regions. "
    "Reply ONLY with a JSON object: "
    '{"findings": [{"claim": "<short>", "iocs": ["..."]}]}.'
)


async def memory_node(state: CaseState) -> dict:
    dumps = [
        e for e in (state.get("evidence") or [])
        if e.get("sha256") and (e.get("path", "").lower().endswith(
            (".mem", ".vmem", ".dmp", ".lime", ".raw_mem"))
            or (e.get("mime") or "").startswith("memory"))
    ]
    if not dumps:
        return {}
    tools = await get_tools_for_worker("memory")
    targets = [{"path": e["path"], "sha256": e["sha256"]} for e in dumps]
    result = await run_react(
        name="memory", tools=tools, prompt=PROMPT,
        task=f"Analyse memory dumps: {json.dumps(targets)}",
        doing=f"memory triage on {len(dumps)} dump(s)",
    )

    obj = parse_first_json(final_text(result)) or {}
    rows = obj.get("findings") if isinstance(obj, dict) else None
    refs = [e["sha256"] for e in dumps]
    findings = []
    if isinstance(rows, list):
        for r in rows:
            if not isinstance(r, dict) or not r.get("claim"):
                continue
            findings.append(make_finding(
                produced_by="memory", claim=r["claim"],
                evidence_refs=refs, messages=result["messages"],
            ))
    return {"findings": findings}
