from __future__ import annotations

import json

from console_logger import log
from mcp_client import get_tools_for_worker
from state import CaseState
from workers._base import final_text, parse_first_json, run_react

PROMPT = (
    "You are DefenseMapper. For each finding's attack_techniques, look up "
    "the D3FEND defenses that map to them with list_defenses_for_attack, "
    "then verify each with get_defense. "
    "Reply ONLY with a JSON object: "
    '{"patches": [{"id": "<finding-id>", "d3fend_defenses": ["D3-AMED"]}]}.'
)


async def defense_map_node(state: CaseState) -> dict:
    findings = state.get("findings") or []
    pending = [
        f for f in findings
        if f.get("attack_techniques") and not f.get("d3fend_defenses")
    ]
    if not pending:
        log.info("defense_map", "no findings to map")
        return {"phase": "defend"}

    tools = await get_tools_for_worker("defense_map")
    items = [
        {"id": f["id"], "attack_techniques": f["attack_techniques"]}
        for f in pending
    ]
    result = await run_react(
        name="defense_map", tools=tools, prompt=PROMPT,
        task=f"Map these findings to D3FEND:\n{json.dumps(items, indent=2)}",
        doing=f"mapping {len(items)} finding(s) to D3FEND",
    )

    obj = parse_first_json(final_text(result)) or {}
    raw_patches = obj.get("patches") if isinstance(obj, dict) else None
    patches = []
    if isinstance(raw_patches, list):
        for p in raw_patches:
            if not isinstance(p, dict): continue
            fid = p.get("id")
            defs = p.get("d3fend_defenses") or []
            if fid and isinstance(defs, list):
                patches.append({"id": fid, "d3fend_defenses": defs})
    log.info("defense_map", f"mapped {len(patches)}/{len(pending)} finding(s)")
    return {"findings": patches, "phase": "defend"}
