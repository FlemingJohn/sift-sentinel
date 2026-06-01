from __future__ import annotations

import json

from mcp_client import get_tools_for_worker
from state import CaseState
from workers._base import final_text, make_finding, parse_first_json, run_react

PROMPT = (
    "You are WindowsArtifactAnalyst. Parse Windows event logs (evtxexport), "
    "registry hives (regfexport, regfinfo), prefetch, $MFT, scheduled tasks, "
    "PST mailboxes (pffexport), ESE databases (esedbexport, including SRUM "
    "and WebCacheV01). Build a timeline with log2timeline_py/psort_py when "
    "useful. Focus on: persistence keys, LOLBin executions (powershell, "
    "wmic, mshta, regsvr32), service installs, lateral movement events "
    "(4624/4648/4672), and scheduled-task creation (4698). "
    "Reply ONLY with a JSON object: "
    '{"findings": [{"claim": "<short>", "evt_id": <int|null>, "key": "<reg key|null>"}],'
    ' "has_windows_evt": <bool>}.'
)


async def windows_node(state: CaseState) -> dict:
    disks = [e for e in (state.get("evidence") or []) if e.get("sha256")]
    if not disks:
        return {}
    tools = await get_tools_for_worker("windows")
    targets = [{"path": e["path"], "sha256": e["sha256"]} for e in disks]
    result = await run_react(
        name="windows", tools=tools, prompt=PROMPT,
        task=f"Analyse Windows artifacts in: {json.dumps(targets)}",
        doing=f"windows-artifact triage on {len(disks)} image(s)",
    )

    obj = parse_first_json(final_text(result)) or {}
    rows = obj.get("findings") if isinstance(obj, dict) else None
    refs = [e["sha256"] for e in disks]
    findings = []
    if isinstance(rows, list):
        for r in rows:
            if not isinstance(r, dict) or not r.get("claim"):
                continue
            findings.append(make_finding(
                produced_by="windows", claim=r["claim"],
                evidence_refs=refs, messages=result["messages"],
                confidence="probable",
            ))
    has_evt = bool(obj.get("has_windows_evt")) if isinstance(obj, dict) else False
    return {"findings": findings, "has_windows_evt": has_evt}
