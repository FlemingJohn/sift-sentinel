from __future__ import annotations

import json

from console_logger import log
from mcp_client import get_tools_for_worker
from state import CaseState
from workers._base import final_text, parse_first_json, run_react

PROMPT = (
    "You are AttackMapper. For each finding, identify MITRE ATT&CK "
    "technique IDs (T1234 or T1234.567) that best fit. Use "
    "map_finding_to_technique on the claim, then validate with "
    "get_technique_details. Prefer specific sub-techniques. "
    "Reply ONLY with a JSON object: "
    '{"patches": [{"id": "<finding-id>", "attack_techniques": ["T1059.001"]}]}.'
)


async def attack_map_node(state: CaseState) -> dict:
    findings = state.get("findings") or []
    pending = [f for f in findings if not f.get("attack_techniques")]
    if not pending:
        log.info("attack_map", "no findings to map")
        return {"phase": "attribute"}

    tools = await get_tools_for_worker("attack_map")
    items = [{"id": f["id"], "claim": f["claim"]} for f in pending]
    result = await run_react(
        name="attack_map", tools=tools, prompt=PROMPT,
        task=f"Map these findings to ATT&CK:\n{json.dumps(items, indent=2)}",
        doing=f"mapping {len(items)} finding(s) to ATT&CK",
    )

    obj = parse_first_json(final_text(result)) or {}
    raw_patches = obj.get("patches") if isinstance(obj, dict) else None
    patches = []
    if isinstance(raw_patches, list):
        for p in raw_patches:
            if not isinstance(p, dict): continue
            fid = p.get("id")
            techs = p.get("attack_techniques") or []
            if fid and isinstance(techs, list) and techs:
                patches.append({"id": fid, "attack_techniques": techs})
    log.info("attack_map", f"mapped {len(patches)}/{len(pending)} finding(s)")
    return {"findings": patches, "phase": "attribute"}
