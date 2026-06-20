"""
sift_defend.py — MITRE D3FEND MCP server

Loads the local D3FEND extraction at startup:
  - 273 per-technique JSON records (api/technique/d3f:*.json)
  - the precomputed ATT&CK ↔ D3FEND mappings (14,003 rows)

Builds in-memory indexes and exposes forensic-action-named tools so an
analyst can answer "given this attack, what defends against it?" without
any network access during an incident.
"""

from __future__ import annotations

import json
import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from shared import AuditLogger, OutputTruncator

mcp   = FastMCP("sift-defend")
audit = AuditLogger("sift-defend")
trunc = OutputTruncator(max_chars=50_000)


# ── data location ────────────────────────────────────────────────────────────

DEFAULT_D3F_DIR = Path(__file__).resolve().parent.parent / "mitre-defend"
D3F_DIR = Path(os.environ.get("SIFT_D3FEND_DIR", DEFAULT_D3F_DIR))

TECH_DIR     = D3F_DIR / "techniques"
MAPPINGS_FILE = D3F_DIR / "d3fend-full-mappings.json"


# ── indexes ──────────────────────────────────────────────────────────────────

DEFENSE_INDEX:    dict[str, dict] = {}                   # "D3-AMED" → defense record
LABEL_TO_ID:      dict[str, str] = {}                    # "Access Mediation" → "D3-AMED"
URI_TO_ID:        dict[str, str] = {}                    # "d3f:AccessMediation" → "D3-AMED"
ATTACK_TO_DEFEND: dict[str, list[dict]] = defaultdict(list)   # "T1059.001" → [{d3_id, label, tactic, artifact}, ...]
TACTIC_INDEX:     dict[str, list[str]] = defaultdict(list)    # "Harden" → ["D3-AMED", ...]
ARTIFACT_INDEX:   dict[str, set[str]] = defaultdict(set)      # "Process" → {"D3-XXX", ...}


# ── loaders ──────────────────────────────────────────────────────────────────

def _local_uri(uri: str) -> str:
    """
    Normalize a URI to its bare local name.
      http://d3fend.mitre.org/ontologies/d3fend.owl#TokenBinding → TokenBinding
      d3f:TokenBinding                                           → TokenBinding
    """
    s = (uri or "").rsplit("#", 1)[-1]
    if s.startswith("d3f:"):
        s = s[4:]
    return s


def _bindings(field: dict | None) -> list[dict]:
    """Per-technique D3FEND fields wrap SPARQL results — pull the binding rows."""
    if not isinstance(field, dict):
        return []
    return ((field.get("results") or {}).get("bindings") or [])


def _graph(field: dict | None) -> list[dict]:
    """JSON-LD wrapper — pull the @graph list."""
    if not isinstance(field, dict):
        return []
    return field.get("@graph") or []


def _val(cell: dict | None) -> str | None:
    """SPARQL binding cell → its value string."""
    if isinstance(cell, dict):
        return cell.get("value")
    return None


def _load_techniques() -> int:
    if not TECH_DIR.is_dir():
        print(f"[sift-defend] WARNING: technique directory missing at {TECH_DIR}")
        return 0
    count = 0
    for fp in TECH_DIR.glob("d3f:*.json"):
        try:
            doc = json.loads(fp.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[sift-defend] skip {fp.name}: {e}")
            continue
        graph = (doc.get("description") or {}).get("@graph") or []
        if not graph:
            continue
        rec = graph[0]
        d3id  = rec.get("d3f:d3fend-id")
        label = rec.get("rdfs:label")
        uri   = rec.get("@id")
        if not d3id or not label:
            continue

        # Extract distinct artifact labels for this defense's local subgraph
        artifact_labels = sorted({
            _val(row.get("def_artifact_label"))
            for row in _bindings(doc.get("digital_artifacts"))
            if _val(row.get("def_artifact_label"))
        })
        # Reference titles only — drop the JSON-LD machinery
        ref_titles = []
        for ref in _graph(doc.get("references"))[:10]:
            if isinstance(ref, dict):
                title = ref.get("rdfs:label") or ref.get("dcterms:title")
                if title:
                    ref_titles.append(title)

        DEFENSE_INDEX[d3id] = {
            "id":             d3id,
            "label":          label,
            "uri":            uri,
            "definition":     (rec.get("d3f:definition") or "")[:1500],
            "tactic":         _local_uri(((rec.get("d3f:enables") or {}) or {}).get("@id", "")) or None,
            "synonym":        rec.get("d3f:synonym"),
            "subclass_of":    _local_uri(((rec.get("rdfs:subClassOf") or {}) or {}).get("@id", "")) or None,
            "artifact_labels": artifact_labels,
            "weakness_count": len(_bindings(doc.get("weaknesses"))),
            "reference_titles": ref_titles,
        }
        LABEL_TO_ID[label] = d3id
        if uri:
            URI_TO_ID[uri] = d3id
            URI_TO_ID[_local_uri(uri)] = d3id   # also "AccessMediation" → "D3-AMED"
        tactic = DEFENSE_INDEX[d3id]["tactic"]
        if tactic:
            TACTIC_INDEX[tactic].append(d3id)

        # global artifact → defenses reverse index
        for a_label in artifact_labels:
            ARTIFACT_INDEX[a_label].add(d3id)

        count += 1
    return count


def _load_mappings() -> int:
    if not MAPPINGS_FILE.is_file():
        print(f"[sift-defend] WARNING: mappings file missing at {MAPPINGS_FILE}")
        return 0
    raw = json.loads(MAPPINGS_FILE.read_text(encoding="utf-8"))
    rows = raw.get("results", {}).get("bindings", [])
    count = 0
    seen: set[tuple[str, str]] = set()
    for r in rows:
        aid = r.get("off_tech_id", {}).get("value")
        if not aid:
            continue
        def_label = r.get("def_tech_label", {}).get("value")
        def_tactic = r.get("def_tactic_label", {}).get("value")
        artifact  = r.get("def_artifact_label", {}).get("value")
        def_uri   = r.get("def_tech", {}).get("value")
        d3id = LABEL_TO_ID.get(def_label) or URI_TO_ID.get(_local_uri(def_uri or ""))
        # de-dup (technique, defense) pairs
        key = (aid, d3id or def_label or "")
        if key in seen:
            continue
        seen.add(key)
        ATTACK_TO_DEFEND[aid].append({
            "d3_id":    d3id,
            "label":    def_label,
            "tactic":   def_tactic,
            "artifact": artifact,
        })
        count += 1
    return count


def _build_indexes() -> dict:
    t0 = time.time()
    n_def = _load_techniques()
    t1 = time.time()
    n_map = _load_mappings()
    t2 = time.time()
    elapsed = t2 - t0

    summary = {
        "defenses_loaded":            len(DEFENSE_INDEX),
        "defenses_load_s":            round(t1 - t0, 2),
        "mapping_rows":               n_map,
        "mappings_load_s":            round(t2 - t1, 2),
        "attack_techniques_covered":  len(ATTACK_TO_DEFEND),
        "tactics":                    sorted(TACTIC_INDEX.keys()),
        "artifacts_indexed":          len(ARTIFACT_INDEX),
        "elapsed_s":                  round(elapsed, 2),
    }
    print(f"[sift-defend] loaded {n_def} D3FEND defenses in {t1 - t0:.2f}s")
    print(f"[sift-defend] loaded {n_map} ATT&CK↔D3FEND mappings in {t2 - t1:.2f}s")
    print(f"[sift-defend] ready: {len(ATTACK_TO_DEFEND)} ATT&CK techniques have at least one D3FEND mapping")
    return summary


# ── helpers ──────────────────────────────────────────────────────────────────

def _envelope(tool: str, data: dict, forensic_note: str) -> dict:
    entry = {
        "tool":          tool,
        "server":        "sift-defend",
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "data":          data,
        "forensic_note": forensic_note,
    }
    audit.log({k: entry[k] for k in ("tool", "server", "timestamp")} | {"input_keys": list(data.keys())[:5]})
    return entry


# ── tools ────────────────────────────────────────────────────────────────────

@mcp.tool()
def get_defense(defense_id: str) -> dict:
    """
    Look up a single D3FEND defensive technique by ID (D3-AMED), label
    ("Access Mediation"), or URI fragment ("AccessMediation").
    """
    if not defense_id:
        return _envelope("get_defense",
                         {"defense_id": defense_id, "found": False},
                         "Provide a defense ID, label, or URI fragment.")
    d = (DEFENSE_INDEX.get(defense_id)
         or DEFENSE_INDEX.get(LABEL_TO_ID.get(defense_id, ""))
         or DEFENSE_INDEX.get(URI_TO_ID.get(defense_id, ""))
         or DEFENSE_INDEX.get(URI_TO_ID.get(defense_id.replace("d3f:", ""), "")))
    if not d:
        return _envelope("get_defense",
                         {"defense_id": defense_id, "found": False},
                         "Unknown defense. 273 D3FEND defensive techniques are indexed.")
    return _envelope(
        "get_defense",
        {"defense_id": d["id"], "found": True, "defense": d},
        "Use list_defenses_for_attack() to find which ATT&CK techniques this defends against.",
    )


@mcp.tool()
def list_defenses_for_attack(technique_id: str) -> dict:
    """
    Given an ATT&CK technique ID (T1059.001), list all D3FEND defenses that
    map to it. Returns empty list for unmapped techniques — including ALL
    ICS techniques (T0xxx), which D3FEND does not yet cover.
    """
    tid = (technique_id or "").strip().upper()
    if not tid:
        return _envelope("list_defenses_for_attack",
                         {"technique_id": technique_id, "defenses": []},
                         "Provide a non-empty ATT&CK technique ID.")
    rows = ATTACK_TO_DEFEND.get(tid, [])
    # enrich with full DEFENSE_INDEX record
    enriched = []
    for r in rows:
        rec = {**r}
        if r.get("d3_id") and r["d3_id"] in DEFENSE_INDEX:
            d = DEFENSE_INDEX[r["d3_id"]]
            rec["definition"] = d["definition"][:500]
        enriched.append(rec)
    note = (f"{len(enriched)} D3FEND defense(s) map to {tid}."
            if enriched
            else f"No D3FEND coverage for {tid}. "
                 f"D3FEND has gaps — all ICS T0xxx techniques and many mobile-only techniques are unmapped.")
    return _envelope(
        "list_defenses_for_attack",
        {"technique_id": tid, "count": len(enriched), "defenses": enriched},
        note,
    )


@mcp.tool()
def list_defenses_by_tactic(tactic: str) -> dict:
    """
    Every D3FEND defense under a tactic. Tactics: Harden, Detect, Isolate,
    Deceive, Evict, Restore, Model.
    """
    t = (tactic or "").strip().title()
    ids = TACTIC_INDEX.get(t, [])
    out = []
    for did in sorted(ids):
        d = DEFENSE_INDEX.get(did)
        if d:
            out.append({
                "id":         d["id"],
                "label":      d["label"],
                "definition": d["definition"][:300],
                "synonym":    d.get("synonym"),
            })
    return _envelope(
        "list_defenses_by_tactic",
        {"tactic": t, "count": len(out), "defenses": out},
        f"D3FEND tactics organize countermeasures along the defensive lifecycle. "
        f"Found {len(out)} defenses under '{t}'.",
    )


@mcp.tool()
def find_defenses_for_artifact(artifact: str) -> dict:
    """
    Given a digital artifact label (e.g. "Process", "Access Token",
    "PowerShell Script"), return the D3FEND defenses that observe or
    protect it.
    """
    if not artifact:
        return _envelope("find_defenses_for_artifact",
                         {"artifact": artifact, "defenses": []},
                         "Provide an artifact label like 'Process' or 'Access Token'.")
    target = artifact.strip().lower()
    matches = set()
    for label, ids in ARTIFACT_INDEX.items():
        if target in label.lower():
            matches |= ids
    out = []
    for did in sorted(matches):
        d = DEFENSE_INDEX.get(did)
        if d:
            out.append({
                "id":         d["id"],
                "label":      d["label"],
                "tactic":     d.get("tactic"),
                "definition": d["definition"][:300],
            })
    return _envelope(
        "find_defenses_for_artifact",
        {"artifact": artifact, "count": len(out), "defenses": out},
        f"D3FEND defenses that touch the '{artifact}' artifact. "
        "Use this when you have evidence but don't yet know the technique.",
    )


@mcp.tool()
def get_attack_to_defend_coverage() -> dict:
    """
    Global view: how many ATT&CK techniques have at least one D3FEND
    mapping, broken down by domain prefix.
    """
    by_prefix: dict[str, int] = defaultdict(int)
    for tid in ATTACK_TO_DEFEND:
        if tid.startswith("T0"):
            by_prefix["T0xxx (ICS)"] += 1
        elif tid.startswith("T1"):
            by_prefix["T1xxx (Enterprise/Mobile)"] += 1
        else:
            by_prefix["other"] += 1
    avg = round(
        sum(len(v) for v in ATTACK_TO_DEFEND.values()) / max(1, len(ATTACK_TO_DEFEND)),
        1,
    )
    return _envelope(
        "get_attack_to_defend_coverage",
        {
            "covered_techniques":  len(ATTACK_TO_DEFEND),
            "by_prefix":           dict(by_prefix),
            "avg_defenses_per_covered_technique": avg,
            "defenses_indexed":    len(DEFENSE_INDEX),
            "tactics":             sorted(TACTIC_INDEX.keys()),
        },
        "Coverage snapshot. Use this to plan triage: an ATT&CK technique not in the covered set "
        "needs a manual countermeasure decision — D3FEND can't help yet.",
    )


# ── server entry point ───────────────────────────────────────────────────────

_STARTUP = _build_indexes()


def main():
    """Console-script entry point used by pyproject.toml [project.scripts]."""
    mcp.run()


if __name__ == "__main__":
    main()
