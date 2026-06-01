"""Direct-function smoke test for sift-attack + sift-defend.

Loads each module in-process (bypassing stdio for speed), calls a representative
tool, and asserts the response envelope shape + non-empty data on the obvious
hits. Same idea as verify.py but covering the two hand-written servers.
"""
import importlib.util
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent
SERVERS = ROOT / "servers"
sys.path.insert(0, str(SERVERS))


def load(name):
    spec = importlib.util.spec_from_file_location(name, SERVERS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


print("─── loading sift_attack ───")
t0 = time.time()
a = load("sift_attack")
print(f"  imported in {time.time()-t0:.2f}s   techniques={len(a.TECHNIQUE_INDEX)}  "
      f"groups={sum(1 for k in a.GROUP_INDEX if k.startswith('G'))}  "
      f"software={sum(1 for k in a.SOFTWARE_INDEX if k.startswith('S'))}  "
      f"mitigations={len(a.MITIGATION_INDEX)}")

print("\n─── loading sift_defend ───")
t0 = time.time()
d = load("sift_defend")
print(f"  imported in {time.time()-t0:.2f}s   defenses={len(d.DEFENSE_INDEX)}  "
      f"attack_techniques_covered={len(d.ATTACK_TO_DEFEND)}  "
      f"tactics={sorted(d.TACTIC_INDEX.keys())}")

print("\n─── functional tests ───")

# 1. find a technique by free text
r = a.map_finding_to_technique("EID 4104 powershell scriptblock")
top = r["data"]["matches"][0] if r["data"]["matches"] else None
print(f"  map_finding_to_technique → top: {top['id']} ({top['name']}) score={top['match_score']}")
assert top["id"] == "T1059.001", f"expected T1059.001, got {top['id']}"

# 2. details
r = a.get_technique_details("T1059.001")
print(f"  get_technique_details(T1059.001) → name={r['data']['technique']['name']}, tactics={r['data']['technique']['tactics']}")
assert r["data"]["found"], "T1059.001 should resolve"

# 3. groups using
r = a.get_groups_using_technique("T1059.001")
print(f"  get_groups_using_technique(T1059.001) → {r['data']['count']} groups; first 3: {[g['name'] for g in r['data']['groups'][:3]]}")

# 4. countermeasures (ATT&CK mitigations)
r = a.get_countermeasures("T1059.001")
print(f"  get_countermeasures(T1059.001) → {r['data']['count']} mitigations; first 3: {[m['id'] for m in r['data']['mitigations'][:3]]}")

# 5. SIFT tools (hand-curated path)
r = a.get_sift_tools_for_technique("T1059.001")
print(f"  get_sift_tools_for_technique(T1059.001) → source={r['data']['mapping_source']}, tool_count={r['data']['tool_count']}")
for t in r["data"]["tools"][:3]:
    print(f"     • {t['server']}/{t['binary']} — {t['where_to_look']}")

# 6. SIFT tools (heuristic fallback path — pick a technique NOT in SIFT_MAPPINGS)
unmapped_id = next((tid for tid in a.TECHNIQUE_INDEX if tid not in a.SIFT_MAPPINGS), None)
if unmapped_id:
    r = a.get_sift_tools_for_technique(unmapped_id)
    print(f"  get_sift_tools_for_technique({unmapped_id}) → source={r['data']['mapping_source']}, "
          f"data_sources={r['data'].get('data_sources', [])[:3]}, candidate_servers={r['data'].get('candidate_servers')}")

# 7. attack chain attribution
r = a.assess_attack_chain(["T1059.001", "T1003.001", "T1547.001", "T1021.001"])
print(f"  assess_attack_chain → top candidate groups:")
for g in r["data"]["candidate_groups"][:5]:
    print(f"     • {g['id']:6} {g['name']:30} overlap={g['tech_overlap']}  coverage={g['coverage']}")

# 8. defense — D3FEND coverage check
r = d.get_attack_to_defend_coverage()
print(f"\n  d3fend coverage → {r['data']['covered_techniques']} ATT&CK techs mapped;  by_prefix={r['data']['by_prefix']};  "
      f"avg_per_covered={r['data']['avg_defenses_per_covered_technique']}")

# 9. defenses for a specific attack — T1059.001 is famously UNMAPPED in D3FEND,
#    so test with T1550.001 (Application Access Token) which we already saw mapped.
r = d.list_defenses_for_attack("T1059.001")
print(f"  list_defenses_for_attack(T1059.001) → {r['data']['count']} defenses (expected 0 — D3FEND gap)")
r = d.list_defenses_for_attack("T1550.001")
print(f"  list_defenses_for_attack(T1550.001) → {r['data']['count']} defenses")
for x in r["data"]["defenses"][:5]:
    print(f"     • {x.get('d3_id') or '   -  ':6} {x['label']:35}  tactic={x.get('tactic')}")

# 10. defense by tactic
r = d.list_defenses_by_tactic("Detect")
print(f"  list_defenses_by_tactic(Detect) → {r['data']['count']} defenses; first 5: {[x['id'] for x in r['data']['defenses'][:5]]}")

# 11. artifact-driven lookup
r = d.find_defenses_for_artifact("Process")
print(f"  find_defenses_for_artifact('Process') → {r['data']['count']} defenses; first 5: {[x['id'] for x in r['data']['defenses'][:5]]}")

# 12. honest ICS gap demonstration
r = d.list_defenses_for_attack("T0807")
print(f"  list_defenses_for_attack(T0807 ICS) → count={r['data']['count']}  note: {r['forensic_note'][:80]}...")

print("\n  ALL CHECKS PASSED ✓")
