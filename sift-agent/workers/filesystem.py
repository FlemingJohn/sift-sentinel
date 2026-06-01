from __future__ import annotations

import json

from mcp_client import get_tools_for_worker
from state import CaseState
from workers._base import final_text, make_finding, parse_first_json, run_react

PROMPT = (
    "You are FilesystemAnalyst. Given disk images, enumerate partitions "
    "(mmls), inspect filesystems (fsstat), list directories (fls -r), "
    "extract suspicious files (icat) and gather MFT/inode metadata. "
    "Look for: unsigned executables in odd paths, recently-modified "
    "system binaries, suspicious scheduled-task XML, ADS streams, "
    "deleted-but-recoverable suspicious files. "
    "Reply ONLY with a JSON object: "
    '{"findings": [{"claim": "<short>", "candidate_files": ["/path/in/image"]}]}.'
)


async def filesystem_node(state: CaseState) -> dict:
    disks = [
        e for e in (state.get("evidence") or [])
        if e.get("sha256")
    ]
    if not disks:
        return {}
    tools = await get_tools_for_worker("filesystem")
    targets = [{"path": e["path"], "sha256": e["sha256"]} for e in disks]
    task = (
        "Analyse these disk images for forensic findings. "
        f"Images: {json.dumps(targets)}"
    )
    result = await run_react(
        name="filesystem", tools=tools, prompt=PROMPT, task=task,
        doing=f"walking {len(disks)} disk image(s)",
    )

    obj = parse_first_json(final_text(result)) or {}
    rows = obj.get("findings") if isinstance(obj, dict) else None
    findings = []
    candidates: list[str] = []
    refs = [e["sha256"] for e in disks]
    if isinstance(rows, list):
        for r in rows:
            if not isinstance(r, dict) or not r.get("claim"):
                continue
            findings.append(make_finding(
                produced_by="filesystem",
                claim=r["claim"],
                evidence_refs=refs,
                messages=result["messages"],
                confidence="weak",
            ))
            for cf in r.get("candidate_files") or []:
                if isinstance(cf, str):
                    candidates.append(cf)

    return {"findings": findings, "candidate_files": candidates}
