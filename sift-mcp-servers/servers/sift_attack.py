"""
sift_attack.py — MITRE ATT&CK MCP server

Loads enterprise + ICS + mobile ATT&CK STIX 2.x bundles at startup, builds
in-memory indexes, exposes forensic-action-named tools that an IR analyst
(or Claude on their behalf) can call without any network access.

Naming convention: tool function names describe the *forensic action*, not
the STIX object type. Examples:
    map_finding_to_technique(finding)      ← "I saw EID 4104, what is this?"
    get_groups_using_technique(tid)        ← "who actually does this?"
    get_sift_tools_for_technique(tid)      ← "what SIFT binaries surface this?"
"""

from __future__ import annotations

import json
import os
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from shared          import AuditLogger, OutputTruncator
from sift_attack_map import SIFT_MAPPINGS, DATA_SOURCE_TO_SERVER

mcp   = FastMCP("sift-attack")
audit = AuditLogger("sift-attack")
trunc = OutputTruncator(max_chars=50_000)


# ── data location ────────────────────────────────────────────────────────────

DEFAULT_STIX_DIR = Path(__file__).resolve().parent.parent / "mitre-attack"
STIX_DIR = Path(os.environ.get("SIFT_ATTACK_STIX_DIR", DEFAULT_STIX_DIR))

DOMAIN_FILES = {
    "enterprise": STIX_DIR / "enterprise-attack.json",
    "ics":        STIX_DIR / "ics-attack.json",
    "mobile":     STIX_DIR / "mobile-attack.json",
}


# ── indexes (populated at startup) ───────────────────────────────────────────

TECHNIQUE_INDEX:  dict[str, dict] = {}    # "T1059.001" → stix attack-pattern
TACTIC_INDEX:     dict[str, list[dict]] = defaultdict(list)  # "execution" → [tech]
GROUP_INDEX:      dict[str, dict] = {}    # "APT29" / "G0016" → intrusion-set
SOFTWARE_INDEX:   dict[str, dict] = {}    # "Mimikatz" / "S0002" → malware|tool
MITIGATION_INDEX: dict[str, dict] = {}    # "M1038" → course-of-action
DATASRC_INDEX:    dict[str, dict] = {}    # stix-id → x-mitre-data-source
DATACOMP_INDEX:   dict[str, dict] = {}    # stix-id → x-mitre-data-component
ANALYTIC_INDEX:   dict[str, dict] = {}    # stix-id → x-mitre-analytic
DETSTRAT_INDEX:   dict[str, dict] = {}    # stix-id → x-mitre-detection-strategy

# graph adjacency (relationship type → list of (source_ref, target_ref))
REL_BY_TYPE_SRC: dict[tuple[str, str], list[str]] = defaultdict(list)   # (rel_type, src_id) → [target_ids]
REL_BY_TYPE_DST: dict[tuple[str, str], list[str]] = defaultdict(list)   # (rel_type, tgt_id) → [source_ids]

# stix-id → primary external_id (T1059.001, G0016, M1038, etc.)
STIX_TO_EXT: dict[str, str] = {}
EXT_TO_STIX: dict[str, str] = {}

DOMAINS_LOADED: list[str] = []


# ── loader ───────────────────────────────────────────────────────────────────

def _ext_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _load_bundle(domain: str, path: Path) -> int:
    if not path.is_file():
        print(f"[sift-attack] WARNING: {domain} bundle missing at {path}")
        return 0
    bundle = json.loads(path.read_text(encoding="utf-8"))
    count = 0
    for obj in bundle.get("objects", []):
        typ = obj.get("type")
        sid = obj.get("id")
        ext = _ext_id(obj)
        if ext:
            STIX_TO_EXT[sid] = ext
            EXT_TO_STIX[ext] = sid

        if typ == "attack-pattern":
            if ext:
                TECHNIQUE_INDEX[ext] = obj
            for kc in obj.get("kill_chain_phases", []) or []:
                TACTIC_INDEX[kc["phase_name"]].append(obj)
        elif typ == "intrusion-set":
            if ext:
                GROUP_INDEX[ext] = obj
            GROUP_INDEX[obj.get("name", "")] = obj
        elif typ in ("malware", "tool"):
            if ext:
                SOFTWARE_INDEX[ext] = obj
            SOFTWARE_INDEX[obj.get("name", "")] = obj
        elif typ == "course-of-action":
            if ext:
                MITIGATION_INDEX[ext] = obj
        elif typ == "x-mitre-data-source":
            DATASRC_INDEX[sid] = obj
        elif typ == "x-mitre-data-component":
            DATACOMP_INDEX[sid] = obj
        elif typ == "x-mitre-analytic":
            ANALYTIC_INDEX[sid] = obj
        elif typ == "x-mitre-detection-strategy":
            DETSTRAT_INDEX[sid] = obj
        elif typ == "relationship":
            rtype = obj.get("relationship_type", "")
            src   = obj.get("source_ref", "")
            tgt   = obj.get("target_ref", "")
            REL_BY_TYPE_SRC[(rtype, src)].append(tgt)
            REL_BY_TYPE_DST[(rtype, tgt)].append(src)
        count += 1
    DOMAINS_LOADED.append(domain)
    return count


def _build_indexes() -> dict:
    t0 = time.time()
    counts = {}
    for dom, path in DOMAIN_FILES.items():
        c0 = time.time()
        counts[dom] = _load_bundle(dom, path)
        print(f"[sift-attack] loaded {dom:<10} : {counts[dom]:>6} objects in {time.time()-c0:.2f}s")

    elapsed = time.time() - t0
    summary = {
        "domains_loaded":      DOMAINS_LOADED,
        "total_objects":       sum(counts.values()),
        "techniques":          len(TECHNIQUE_INDEX),
        "groups":              sum(1 for k in GROUP_INDEX if k.startswith("G")),
        "software":            sum(1 for k in SOFTWARE_INDEX if k.startswith("S")),
        "mitigations":         len(MITIGATION_INDEX),
        "tactics":             len(TACTIC_INDEX),
        "relationships":       sum(len(v) for v in REL_BY_TYPE_SRC.values()),
        "data_sources":        len(DATASRC_INDEX),
        "data_components":     len(DATACOMP_INDEX),
        "analytics":           len(ANALYTIC_INDEX),
        "detection_strategies":len(DETSTRAT_INDEX),
        "elapsed_s":           round(elapsed, 2),
    }
    print(f"[sift-attack] indexed {summary['techniques']} techniques across "
          f"{len(DOMAINS_LOADED)} domains in {elapsed:.2f}s")
    return summary


# ── small helpers ────────────────────────────────────────────────────────────

def _trim(obj: dict) -> dict:
    """Return a small subset of fields suitable for MCP output."""
    return {
        "id":          _ext_id(obj),
        "stix_id":     obj.get("id"),
        "name":        obj.get("name"),
        "description": (obj.get("description") or "")[:500],
        "type":        obj.get("type"),
        "platforms":   obj.get("x_mitre_platforms"),
        "tactics":     [kc["phase_name"] for kc in obj.get("kill_chain_phases", []) or []],
        "domain":      obj.get("x_mitre_domains"),
        "revoked":     obj.get("revoked", False),
        "deprecated":  obj.get("x_mitre_deprecated", False),
    }


def _envelope(tool: str, data: dict, forensic_note: str) -> dict:
    """Standard response envelope every tool returns."""
    entry = {
        "tool":          tool,
        "server":        "sift-attack",
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "data":          data,
        "forensic_note": forensic_note,
    }
    audit.log({k: entry[k] for k in ("tool", "server", "timestamp")} | {"input_keys": list(data.keys())[:5]})
    return entry


def _resolve_tid(tid: str) -> str | None:
    """Accept T1059.001, t1059.001, or 'PowerShell' (case-insensitive)."""
    if not tid:
        return None
    tid = tid.strip()
    if tid.upper() in TECHNIQUE_INDEX:
        return tid.upper()
    lower = tid.lower()
    for k, v in TECHNIQUE_INDEX.items():
        if (v.get("name") or "").lower() == lower:
            return k
    return None


# ── tools ────────────────────────────────────────────────────────────────────

@mcp.tool()
def map_finding_to_technique(finding: str) -> dict:
    """
    Given a forensic-evidence string (a tool output snippet, an event-ID
    description, a registry key path, a process command line), return the
    ATT&CK techniques that best match. Searches name + description + aliases.

    Example: map_finding_to_technique("EID 4104 powershell scriptblock")
        → matches T1059.001 (PowerShell), T1059 (Command and Scripting Interpreter)
    """
    if not finding or not finding.strip():
        return _envelope("map_finding_to_technique",
                         {"matches": [], "query": finding},
                         "Provide a non-empty finding string.")

    tokens = [t.lower() for t in re.findall(r"[a-z0-9._/\\-]+", finding.lower()) if len(t) >= 3]
    if not tokens:
        return _envelope("map_finding_to_technique",
                         {"matches": [], "query": finding},
                         "No searchable tokens in input.")

    scored: list[tuple[float, str, dict]] = []
    finding_lc = finding.lower()
    finding_tokens = set(tokens)
    for tid, obj in TECHNIQUE_INDEX.items():
        name_lc = (obj.get("name") or "").lower()
        desc_lc = (obj.get("description") or "")[:1500].lower()
        score = 0.0
        # exact technique ID in the finding text
        if tid.lower() in finding_lc:
            score += 20.0
        # name-coverage ratio: what fraction of the technique's name tokens
        # appear in the finding? perfect coverage on a short name (e.g. "PowerShell")
        # outranks partial coverage on a longer name (e.g. "PowerShell Profile").
        name_tokens = {t for t in re.findall(r"[a-z0-9]+", name_lc) if len(t) >= 3}
        if name_tokens:
            coverage = len(name_tokens & finding_tokens) / len(name_tokens)
            score += coverage * 10.0
        # description hits as a weak tie-breaker
        for tok in finding_tokens:
            if tok in desc_lc:
                score += 0.2
        if score > 0:
            scored.append((score, tid, obj))

    scored.sort(key=lambda x: -x[0])
    matches = [
        {**_trim(obj), "match_score": round(s, 2)}
        for s, _, obj in scored[:8]
    ]
    return _envelope(
        "map_finding_to_technique",
        {"query": finding, "matches": matches, "match_count": len(matches)},
        "Top 8 ATT&CK techniques matching this forensic finding by keyword overlap. "
        "Use map_finding_to_technique() as the first call when you see an unfamiliar IOC.",
    )


@mcp.tool()
def get_technique_details(technique_id: str) -> dict:
    """
    Full record for a specific technique. Accepts ID (T1059.001) or name (PowerShell).
    """
    tid = _resolve_tid(technique_id)
    if tid is None:
        return _envelope("get_technique_details",
                         {"technique_id": technique_id, "found": False},
                         "Unknown technique ID or name. Try a canonical ID like T1059.001.")
    obj = TECHNIQUE_INDEX[tid]
    out = _trim(obj)
    out["description"] = (obj.get("description") or "")[:2500]
    out["data_sources"] = obj.get("x_mitre_data_sources") or []
    out["detection"]    = (obj.get("x_mitre_detection") or "")[:1500]
    return _envelope(
        "get_technique_details",
        {"technique_id": tid, "found": True, "technique": out},
        f"Full ATT&CK record for {tid}. Pair with get_sift_tools_for_technique() to find which SIFT binaries surface evidence.",
    )


@mcp.tool()
def list_techniques_by_tactic(tactic: str) -> dict:
    """
    Every technique mapped to a given tactic (execution, persistence, lateral-movement, ...).
    """
    key = (tactic or "").lower().strip().replace(" ", "-")
    techs = TACTIC_INDEX.get(key, [])
    seen, items = set(), []
    for t in techs:
        ext = _ext_id(t)
        if ext and ext not in seen:
            seen.add(ext)
            items.append(_trim(t))
    items.sort(key=lambda x: x.get("id") or "")
    return _envelope(
        "list_techniques_by_tactic",
        {"tactic": key, "count": len(items), "techniques": items[:200]},
        f"Got {len(items)} techniques under tactic '{key}'. Returned up to 200; query is in-memory and cheap.",
    )


@mcp.tool()
def get_groups_using_technique(technique_id: str) -> dict:
    """
    Threat-actor groups (APT29, FIN7, ...) that have used a given technique.
    """
    tid = _resolve_tid(technique_id)
    if tid is None or tid not in EXT_TO_STIX:
        return _envelope("get_groups_using_technique",
                         {"technique_id": technique_id, "groups": []},
                         "Unknown technique ID.")
    stix = EXT_TO_STIX[tid]
    # relationship: intrusion-set --uses--> attack-pattern
    group_stix_ids = REL_BY_TYPE_DST.get(("uses", stix), [])
    groups = []
    for gid in group_stix_ids:
        ext = STIX_TO_EXT.get(gid)
        if not ext or not ext.startswith("G"):
            continue
        g = GROUP_INDEX.get(ext)
        if g:
            groups.append({
                "id":      ext,
                "name":    g.get("name"),
                "aliases": g.get("aliases") or g.get("x_mitre_aliases") or [],
                "description": (g.get("description") or "")[:300],
            })
    groups.sort(key=lambda x: x["id"])
    return _envelope(
        "get_groups_using_technique",
        {"technique_id": tid, "count": len(groups), "groups": groups},
        f"{len(groups)} threat-actor group(s) documented as using {tid}. Knowing the actor narrows the IR playbook fast.",
    )


@mcp.tool()
def get_software_used_by_group(group: str) -> dict:
    """
    Malware and tools attributed to a threat-actor group. Accepts group ID (G0016) or name.
    """
    g = GROUP_INDEX.get(group) or GROUP_INDEX.get(group.upper()) if group else None
    if not g:
        return _envelope("get_software_used_by_group",
                         {"group": group, "software": []},
                         "Unknown group. Try canonical ID (G0016) or full name (APT29).")
    stix_id = g.get("id")
    sw_ids = REL_BY_TYPE_SRC.get(("uses", stix_id), [])
    software = []
    for sid in sw_ids:
        ext = STIX_TO_EXT.get(sid)
        if not ext or not ext.startswith("S"):
            continue
        s = SOFTWARE_INDEX.get(ext)
        if s:
            software.append({
                "id":   ext,
                "name": s.get("name"),
                "type": s.get("type"),
                "labels": s.get("labels") or [],
            })
    software.sort(key=lambda x: x["id"])
    return _envelope(
        "get_software_used_by_group",
        {"group": g.get("name"), "group_id": _ext_id(g), "count": len(software), "software": software},
        f"{len(software)} malware/tool entries attributed to {g.get('name')}. Use these as IOCs to pivot disk/memory carving.",
    )


@mcp.tool()
def get_countermeasures(technique_id: str) -> dict:
    """
    Mitigations (M-IDs) that ATT&CK documents for a given technique.
    """
    tid = _resolve_tid(technique_id)
    if tid is None or tid not in EXT_TO_STIX:
        return _envelope("get_countermeasures",
                         {"technique_id": technique_id, "mitigations": []},
                         "Unknown technique ID.")
    stix = EXT_TO_STIX[tid]
    mit_ids = REL_BY_TYPE_DST.get(("mitigates", stix), [])
    mits = []
    for mid in mit_ids:
        ext = STIX_TO_EXT.get(mid)
        if not ext or not ext.startswith("M"):
            continue
        m = MITIGATION_INDEX.get(ext)
        if m:
            mits.append({
                "id":          ext,
                "name":        m.get("name"),
                "description": (m.get("description") or "")[:300],
            })
    mits.sort(key=lambda x: x["id"])
    return _envelope(
        "get_countermeasures",
        {"technique_id": tid, "count": len(mits), "mitigations": mits},
        f"ATT&CK lists {len(mits)} mitigation(s) for {tid}. For deeper countermeasure detail, also call sift-defend list_defenses_for_attack().",
    )


@mcp.tool()
def get_sift_tools_for_technique(technique_id: str) -> dict:
    """
    Which SIFT binaries surface forensic evidence of this technique.

    Strategy:
      1. Direct lookup in hand-curated SIFT_MAPPINGS (top-50 operational techniques).
      2. Fallback: walk technique → data-component → data-source and map each
         data-source name to the appropriate SIFT server via heuristic.
    """
    tid = _resolve_tid(technique_id)
    if tid is None:
        return _envelope("get_sift_tools_for_technique",
                         {"technique_id": technique_id, "tools": []},
                         "Unknown technique ID.")

    # 1. direct hit
    if tid in SIFT_MAPPINGS:
        m = SIFT_MAPPINGS[tid]
        tools = [
            {"server": srv, "binary": b, "where_to_look": where}
            for srv, b, where in m["tools"]
        ]
        return _envelope(
            "get_sift_tools_for_technique",
            {
                "technique_id":     tid,
                "mapping_source":   "manual_curation",
                "tool_count":       len(tools),
                "tools":            tools,
                "technique_note":   m["forensic_note"],
            },
            "Hand-curated mapping from the top-50 operationally common ATT&CK techniques.",
        )

    # 2. fallback — walk to data-sources via STIX graph + direct refs
    stix = EXT_TO_STIX.get(tid)
    data_sources: set[str] = set()
    if stix:
        # detection-strategy --detects--> technique
        for ds_stix in REL_BY_TYPE_DST.get(("detects", stix), []):
            strat = DETSTRAT_INDEX.get(ds_stix)
            if not strat:
                continue
            # analytic IDs live directly on detection-strategy (not via relationship)
            for an_stix in strat.get("x_mitre_analytic_refs") or []:
                analytic = ANALYTIC_INDEX.get(an_stix)
                if not analytic:
                    continue
                for ref in analytic.get("x_mitre_log_source_references", []) or []:
                    comp_id = ref.get("x_mitre_data_component_ref")
                    comp = DATACOMP_INDEX.get(comp_id)
                    if not comp:
                        continue
                    # v16: data-component name is the heuristic key (e.g. "Process Creation").
                    # Older bundles also kept x_mitre_data_source_ref — try that too if present.
                    if comp.get("name"):
                        data_sources.add(comp["name"])
                    src_id = comp.get("x_mitre_data_source_ref")
                    if src_id and src_id in DATASRC_INDEX:
                        ds_name = DATASRC_INDEX[src_id].get("name")
                        if ds_name:
                            data_sources.add(ds_name)
        # also pull legacy x_mitre_data_sources field if populated (ICS/Mobile still use it)
        for ds in TECHNIQUE_INDEX[tid].get("x_mitre_data_sources") or []:
            data_sources.add(ds.split(":")[0].strip())

    servers = sorted({DATA_SOURCE_TO_SERVER.get(d) for d in data_sources if DATA_SOURCE_TO_SERVER.get(d)})
    return _envelope(
        "get_sift_tools_for_technique",
        {
            "technique_id":      tid,
            "mapping_source":    "heuristic_via_data_sources",
            "data_sources":      sorted(data_sources),
            "candidate_servers": servers,
            "tools":             [],
            "note":              "No manual mapping for this technique; consider adding one to SIFT_MAPPINGS for sharper output.",
        },
        "Heuristic-only mapping. Tells you which SIFT category is likely to have the evidence, "
        "but not the specific binary. Hand-curate this technique if it's operationally common.",
    )


@mcp.tool()
def assess_attack_chain(technique_ids: list[str]) -> dict:
    """
    Given a list of technique IDs observed in an incident, identify groups
    whose known TTPs intersect most strongly with this chain.
    """
    if not technique_ids:
        return _envelope("assess_attack_chain",
                         {"input": [], "candidate_groups": []},
                         "Provide at least one technique ID.")

    resolved = [t for t in (_resolve_tid(x) for x in technique_ids) if t]
    if not resolved:
        return _envelope("assess_attack_chain",
                         {"input": technique_ids, "candidate_groups": []},
                         "None of the provided IDs resolved.")

    group_hits: dict[str, int] = defaultdict(int)
    for tid in resolved:
        stix = EXT_TO_STIX.get(tid)
        if not stix:
            continue
        for gid in REL_BY_TYPE_DST.get(("uses", stix), []):
            ext = STIX_TO_EXT.get(gid)
            if ext and ext.startswith("G"):
                group_hits[ext] += 1

    ranked = sorted(group_hits.items(), key=lambda x: -x[1])[:10]
    candidates = []
    for gid, hits in ranked:
        g = GROUP_INDEX.get(gid)
        if not g:
            continue
        candidates.append({
            "id":          gid,
            "name":        g.get("name"),
            "tech_overlap": hits,
            "coverage":    round(hits / len(resolved), 2),
            "aliases":     g.get("aliases") or g.get("x_mitre_aliases") or [],
        })
    return _envelope(
        "assess_attack_chain",
        {
            "input_techniques":     resolved,
            "input_count":          len(resolved),
            "candidate_groups":     candidates,
        },
        f"Ranked threat actors by overlap with the {len(resolved)} observed techniques. "
        "Highest coverage is your best initial hypothesis; combine with timing/geo for attribution.",
    )


# ── server entry point ───────────────────────────────────────────────────────

_STARTUP = _build_indexes()


def main():
    """Console-script entry point used by pyproject.toml [project.scripts]."""
    mcp.run()


if __name__ == "__main__":
    main()
