from __future__ import annotations

import json

from mcp_client import get_tools_for_worker
from state import CaseState
from workers._base import final_text, make_finding, parse_first_json, run_react

PROMPT = (
    "You are NetworkPcapAnalyst. Inspect packet captures passively. Use "
    "tcptrace and tcpstat for session summaries, tcpflow to extract "
    "per-stream content, ngrep to pattern-match payloads, p0f for OS "
    "fingerprints, ssldump for TLS metadata. For netflow data, use "
    "nfdump. Focus on: C2 beaconing, DNS exfiltration, unusual TLS SNI, "
    "long-lived sessions to rare destinations. "
    "Reply ONLY with a JSON object: "
    '{"findings": [{"claim": "<short>", "dst_ips": ["..."], "indicators": ["..."]}]}.'
)


async def network_node(state: CaseState) -> dict:
    pcaps = [
        e for e in (state.get("evidence") or [])
        if e.get("sha256") and e.get("path", "").lower().endswith(
            (".pcap", ".pcapng", ".cap"))
    ]
    if not pcaps:
        return {}
    tools = await get_tools_for_worker("network")
    targets = [{"path": e["path"], "sha256": e["sha256"]} for e in pcaps]
    result = await run_react(
        name="network", tools=tools, prompt=PROMPT,
        task=f"Analyse these captures: {json.dumps(targets)}",
        doing=f"pcap analysis on {len(pcaps)} capture(s)",
    )

    obj = parse_first_json(final_text(result)) or {}
    rows = obj.get("findings") if isinstance(obj, dict) else None
    refs = [e["sha256"] for e in pcaps]
    findings = []
    if isinstance(rows, list):
        for r in rows:
            if not isinstance(r, dict) or not r.get("claim"):
                continue
            findings.append(make_finding(
                produced_by="network", claim=r["claim"],
                evidence_refs=refs, messages=result["messages"],
            ))
    return {"findings": findings}
