from __future__ import annotations

from console_logger import log
from mcp_client import get_tools_for_worker
from state import CaseState
from workers._base import (
    append_chain, collect_tool_envelopes, envelope_hash, final_text,
    parse_first_json, run_react,
)

PROMPT = (
    "You are ImageAcquirer. For each evidence path, determine its type "
    "(disk image: E01/AFF/raw/img/dd ; memory dump: mem/vmem/dmp ; "
    "pcap: pcap/pcapng ; other) and size in bytes. "
    "Use ewfinfo for .E01, affinfo for .AFF, disktype for raw images, "
    "tsk_imageinfo when useful. Do not mount anything destructive. "
    "Reply ONLY with a JSON object of the form: "
    '{"images": [{"path": "...", "type": "disk|memory|pcap|other", '
    '"size_bytes": <int>, "mime": "..."}]}.'
)

_DISK_EXTS   = (".e01", ".aff", ".dd", ".raw", ".img", ".001", ".ad1")
_MEMORY_EXTS = (".mem", ".vmem", ".dmp", ".lime", ".raw_mem")
_PCAP_EXTS   = (".pcap", ".pcapng", ".cap")


def _ext_guess(path: str) -> str:
    p = path.lower()
    if p.endswith(_DISK_EXTS):   return "disk"
    if p.endswith(_MEMORY_EXTS): return "memory"
    if p.endswith(_PCAP_EXTS):   return "pcap"
    return "other"


async def acquirer_node(state: CaseState) -> dict:
    evidence = state.get("evidence") or []
    if not evidence:
        return {"phase": "acquire", "halted": True, "halt_reason": "no_evidence"}

    tools = await get_tools_for_worker("acquirer")
    paths = [e["path"] for e in evidence]
    task = (
        "Identify and characterise these evidence files. Return one JSON "
        f"object as specified. Files: {paths}"
    )
    result = await run_react(
        name="acquirer",
        tools=tools,
        prompt=PROMPT,
        task=task,
        doing=f"identifying {len(paths)} evidence file(s)",
    )

    obj = parse_first_json(final_text(result)) or {}
    images = obj.get("images") if isinstance(obj, dict) else None
    by_path: dict[str, dict] = {}
    if isinstance(images, list):
        for img in images:
            if isinstance(img, dict) and img.get("path"):
                by_path[img["path"]] = img

    has_disk = has_mem = has_pcap = False
    patches = []
    envelopes = collect_tool_envelopes(result["messages"])
    for ev in evidence:
        path = ev["path"]
        guess = by_path.get(path, {}).get("type") or _ext_guess(path)
        if guess == "disk":   has_disk = True
        if guess == "memory": has_mem  = True
        if guess == "pcap":   has_pcap = True

        patch = {"path": path, "acquired_by": "acquirer"}
        if path in by_path:
            patch["size_bytes"] = by_path[path].get("size_bytes")
            patch["mime"]       = by_path[path].get("mime")
        for env in envelopes:
            patch = append_chain(
                patch, actor="acquirer",
                tool=env.get("tool") or "unknown",
                envelope_sha=envelope_hash(env),
            )
        patches.append(patch)

    log.info(
        "acquirer",
        f"disk={has_disk} mem={has_mem} pcap={has_pcap}",
    )
    return {
        "evidence": patches,
        "has_disk_image":  has_disk,
        "has_memory_dump": has_mem,
        "has_pcap":        has_pcap,
        "phase": "acquire",
    }
