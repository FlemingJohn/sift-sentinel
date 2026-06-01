from __future__ import annotations

from console_logger import log
from mcp_client import get_tools_for_worker
from state import CaseState
from workers._base import (
    append_chain, collect_tool_envelopes, envelope_hash, final_text,
    parse_first_json, run_react,
)

PROMPT = (
    "You are IntegrityHasher. For every evidence file path, compute the "
    "sha256, md5, and ssdeep (fuzzy) hash using the sift-hashing tools "
    "(sha256deep, md5deep, ssdeep). One tool call per hash family. "
    "Reply ONLY with a JSON object: "
    '{"hashes": [{"path": "...", "sha256": "...", "md5": "...", "ssdeep": "..."}]}.'
)


async def hasher_node(state: CaseState) -> dict:
    evidence = state.get("evidence") or []
    pending = [e for e in evidence if not e.get("sha256")]
    if not pending:
        log.info("hasher", "nothing to hash (all evidence already hashed)")
        return {"phase": "verify"}

    tools = await get_tools_for_worker("hasher")
    paths = [e["path"] for e in pending]
    result = await run_react(
        name="hasher",
        tools=tools,
        prompt=PROMPT,
        task=f"Hash these files and return the JSON manifest: {paths}",
        doing=f"hashing {len(paths)} file(s)",
    )

    obj = parse_first_json(final_text(result)) or {}
    rows = obj.get("hashes") if isinstance(obj, dict) else None
    by_path: dict[str, dict] = {}
    if isinstance(rows, list):
        for r in rows:
            if isinstance(r, dict) and r.get("path"):
                by_path[r["path"]] = r

    envelopes = collect_tool_envelopes(result["messages"])
    patches = []
    for ev in pending:
        match = by_path.get(ev["path"])
        if not match:
            log.error("hasher", f"no hash returned for {ev['path']}")
            continue
        patch = {
            "path": ev["path"],
            "sha256": match.get("sha256"),
            "md5":    match.get("md5"),
            "ssdeep": match.get("ssdeep"),
        }
        for env in envelopes:
            patch = append_chain(
                patch, actor="hasher",
                tool=env.get("tool") or "unknown",
                envelope_sha=envelope_hash(env),
            )
        patches.append(patch)

    return {"evidence": patches, "phase": "verify"}
