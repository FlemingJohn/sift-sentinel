"""Honest count of D3FEND defenses: files on disk vs DEFENSE_INDEX vs ATTACK_TO_DEFEND."""
import json, sys, importlib.util
from pathlib import Path

ROOT = Path("/mnt/c/Users/FlemingJohn/Downloads/sift-mcp-servers/repoistory-reference/d3fend-gh-pages")
TECH = ROOT / "api" / "technique"

files = sorted(TECH.glob("d3f:*.json"))
print(f"─── files on disk ───")
print(f"  d3f:*.json files in api/technique/ : {len(files)}")

# Why might some not get indexed?  Our loader requires d3fend-id + label.
ok = no_d3id = no_label = no_graph = 0
deprecated_count = 0
inferred = 0
sample_skip = []
for fp in files:
    doc = json.loads(fp.read_text())
    graph = (doc.get("description") or {}).get("@graph") or []
    if not graph:
        no_graph += 1
        sample_skip.append((fp.name, "no @graph"))
        continue
    rec = graph[0]
    d3id  = rec.get("d3f:d3fend-id")
    label = rec.get("rdfs:label")
    if not d3id:
        no_d3id += 1
        sample_skip.append((fp.name, f"no d3fend-id, label={label}"))
        continue
    if not label:
        no_label += 1
        sample_skip.append((fp.name, f"no rdfs:label, d3id={d3id}"))
        continue
    if rec.get("owl:deprecated") or rec.get("d3f:deprecated"):
        deprecated_count += 1
    # is this an INFERRED individual (not a published defensive technique)?
    types = rec.get("@type") or []
    if isinstance(types, str):
        types = [types]
    if any("Inferred" in (t or "") for t in types):
        inferred += 1
    ok += 1

print(f"\n─── breakdown by reason ───")
print(f"  indexed                  : {ok}")
print(f"  missing @graph           : {no_graph}")
print(f"  missing d3f:d3fend-id    : {no_d3id}")
print(f"  missing rdfs:label       : {no_label}")
if sample_skip:
    print(f"  sample dropped:")
    for n, why in sample_skip[:5]:
        print(f"    {n:<40}  {why}")

print(f"\n─── mappings file ───")
mp = json.loads((ROOT / "api/ontology/inference/d3fend-full-mappings.json").read_text())
rows = mp["results"]["bindings"]
print(f"  raw SPARQL binding rows                            : {len(rows):,}")

# unique pairs in raw rows
unique_pairs = set()
unique_attack_ids = set()
unique_def_labels = set()
for r in rows:
    aid = r.get("off_tech_id", {}).get("value")
    dl  = r.get("def_tech_label", {}).get("value")
    if aid:
        unique_attack_ids.add(aid)
    if dl:
        unique_def_labels.add(dl)
    if aid and dl:
        unique_pairs.add((aid, dl))
print(f"  unique (attack_id, defense_label) pairs            : {len(unique_pairs):,}")
print(f"  unique ATT&CK technique IDs in mappings            : {len(unique_attack_ids):,}")
print(f"  unique D3FEND defense LABELS in mappings           : {len(unique_def_labels):,}")

# Compare against indexed defenses
sys.path.insert(0, "servers")
spec = importlib.util.spec_from_file_location("sift_defend", "servers/sift_defend.py")
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)
print(f"\n─── what sift-defend actually holds ───")
print(f"  DEFENSE_INDEX entries                              : {len(d.DEFENSE_INDEX)}")
print(f"  LABEL_TO_ID entries                                : {len(d.LABEL_TO_ID)}")
print(f"  ATTACK_TO_DEFEND keys (covered ATT&CK techniques)  : {len(d.ATTACK_TO_DEFEND)}")
total_mappings = sum(len(v) for v in d.ATTACK_TO_DEFEND.values())
print(f"  total (attack→defense) edges in ATTACK_TO_DEFEND   : {total_mappings:,}")

# Mapping labels that didn't resolve to a known D3-XXX
resolved = sum(1 for tid in d.ATTACK_TO_DEFEND for x in d.ATTACK_TO_DEFEND[tid] if x.get("d3_id"))
unresolved = sum(1 for tid in d.ATTACK_TO_DEFEND for x in d.ATTACK_TO_DEFEND[tid] if not x.get("d3_id"))
print(f"    mappings whose label joined to a D3-XXX id       : {resolved:,}")
print(f"    mappings with no D3-XXX (label-only)             : {unresolved:,}")

# defenses that appear in the catalog but have ZERO ATT&CK mappings
mapped_d3_ids = {x["d3_id"] for tid in d.ATTACK_TO_DEFEND for x in d.ATTACK_TO_DEFEND[tid] if x.get("d3_id")}
unmapped_defenses = [did for did in d.DEFENSE_INDEX if did not in mapped_d3_ids]
print(f"\n─── coverage from the defense side ───")
print(f"  defenses with at least one ATT&CK mapping          : {len(mapped_d3_ids)}")
print(f"  defenses with NO ATT&CK mapping                    : {len(unmapped_defenses)}")
print(f"  sample unmapped defenses (first 10):")
for did in sorted(unmapped_defenses)[:10]:
    rec = d.DEFENSE_INDEX[did]
    print(f"    {did:<10}  {rec['label']}")
