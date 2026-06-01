from __future__ import annotations

import json

from mcp_client import get_tools_for_worker
from state import CaseState
from workers._base import final_text, make_finding, parse_first_json, run_react

PROMPT = (
    "You are EncryptionAnalyst. Identify encrypted volumes on disk images: "
    "BitLocker (dislocker_find, dislocker_metadata), FileVault2 (fvdeinfo), "
    "LUKS. For each, report whether a recovery key or BEK file is needed. "
    "Compute volume entropy with histogram to corroborate encryption. "
    "DO NOT attempt password cracking. "
    "Reply ONLY with a JSON object: "
    '{"findings": [{"claim": "<short>", "scheme": "bitlocker|fvde|luks|other"}], '
    '"has_encrypted_volume": <bool>}.'
)


async def crypto_node(state: CaseState) -> dict:
    disks = [e for e in (state.get("evidence") or []) if e.get("sha256")]
    if not disks:
        return {}
    tools = await get_tools_for_worker("crypto")
    targets = [{"path": e["path"], "sha256": e["sha256"]} for e in disks]
    result = await run_react(
        name="crypto", tools=tools, prompt=PROMPT,
        task=f"Detect encryption on: {json.dumps(targets)}",
        doing=f"encryption detection on {len(disks)} image(s)",
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
                produced_by="crypto", claim=r["claim"],
                evidence_refs=refs, messages=result["messages"],
                confidence="probable",
            ))
    has_enc = bool(obj.get("has_encrypted_volume")) if isinstance(obj, dict) else False
    return {"findings": findings, "has_encrypted_volume": has_enc}
