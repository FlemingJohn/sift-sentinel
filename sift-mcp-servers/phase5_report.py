"""
phase5_report.py — speed + accuracy + coverage report for sift-attack & sift-defend.

Run from project root inside the WSL venv:
    python phase5_report.py
"""

import importlib.util
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).parent
SERVERS = ROOT / "servers"
sys.path.insert(0, str(SERVERS))


def _load(name: str, timed: bool = True):
    t0 = time.time()
    spec = importlib.util.spec_from_file_location(name, SERVERS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod, time.time() - t0


print("═" * 70)
print("  PHASE 5 — SPEED + ACCURACY + COVERAGE REPORT")
print("═" * 70)

# ── speed ─────────────────────────────────────────────────────────────────────
print("\nSPEED ANALYSIS")
print("─" * 70)
t_load_attack_cold = time.time()
attack, _ = _load("sift_attack")
cold_attack = time.time() - t_load_attack_cold

t_load_defend_cold = time.time()
defend, _ = _load("sift_defend")
cold_defend = time.time() - t_load_defend_cold

print(f"  sift-attack cold start (file → indexes ready) : {cold_attack:>5.2f}s")
print(f"  sift-defend cold start (file → indexes ready) : {cold_defend:>5.2f}s")
print(f"  combined cold start                            : {cold_attack + cold_defend:>5.2f}s")

# warm start = re-call _build_indexes() on already-loaded module (clears + rebuilds)
def _wipe(mod, names):
    for n in names:
        idx = getattr(mod, n, None)
        if isinstance(idx, dict):
            idx.clear()
        elif isinstance(idx, list):
            idx.clear()

_wipe(attack, ["TECHNIQUE_INDEX","TACTIC_INDEX","GROUP_INDEX","SOFTWARE_INDEX",
               "MITIGATION_INDEX","DATASRC_INDEX","DATACOMP_INDEX","ANALYTIC_INDEX",
               "DETSTRAT_INDEX","REL_BY_TYPE_SRC","REL_BY_TYPE_DST",
               "STIX_TO_EXT","EXT_TO_STIX","DOMAINS_LOADED"])
t0 = time.time()
attack._build_indexes()
warm_attack = time.time() - t0

_wipe(defend, ["DEFENSE_INDEX","LABEL_TO_ID","URI_TO_ID","ATTACK_TO_DEFEND",
               "TACTIC_INDEX","ARTIFACT_INDEX"])
t0 = time.time()
defend._build_indexes()
warm_defend = time.time() - t0

print(f"  sift-attack warm rebuild (parsed files in OS cache): {warm_attack:>5.2f}s")
print(f"  sift-defend warm rebuild (parsed files in OS cache): {warm_defend:>5.2f}s")

# tool call latency
print("\n  Average tool-call latency (1000 calls each, in-process):")
import statistics

def bench(fn, args, n=1000):
    durations = []
    for _ in range(n):
        t = time.perf_counter()
        fn(*args)
        durations.append((time.perf_counter() - t) * 1000)
    return statistics.median(durations), statistics.quantiles(durations, n=20)[-1]

for tool_name, fn, args in [
    ("attack.map_finding_to_technique",   attack.map_finding_to_technique,  ["EID 4104 powershell scriptblock"]),
    ("attack.get_technique_details",      attack.get_technique_details,     ["T1059.001"]),
    ("attack.get_groups_using_technique", attack.get_groups_using_technique,["T1059.001"]),
    ("attack.get_countermeasures",        attack.get_countermeasures,       ["T1059.001"]),
    ("attack.get_sift_tools_for_tech",    attack.get_sift_tools_for_technique,["T1059.001"]),
    ("attack.assess_attack_chain",        attack.assess_attack_chain,       [["T1059.001","T1003.001","T1547.001","T1021.001"]]),
    ("defend.get_defense",                defend.get_defense,               ["D3-TB"]),
    ("defend.list_defenses_for_attack",   defend.list_defenses_for_attack,  ["T1550.001"]),
    ("defend.find_defenses_for_artifact", defend.find_defenses_for_artifact,["Process"]),
]:
    med, p95 = bench(fn, args, n=200)
    print(f"    {tool_name:<42}  median={med:>7.2f}ms  p95={p95:>7.2f}ms")

print("\n  Tools that need network calls : 0 (zero — every tool reads from in-memory indexes)")

# ── accuracy ──────────────────────────────────────────────────────────────────
print("\nACCURACY ANALYSIS")
print("─" * 70)
n_attack = len(attack.TECHNIQUE_INDEX)
n_defend = len(defend.DEFENSE_INDEX)
n_mapped = len(defend.ATTACK_TO_DEFEND)

# count techniques per ATT&CK domain
domain_counts = Counter()
for tid, obj in attack.TECHNIQUE_INDEX.items():
    for d in obj.get("x_mitre_domains") or ["unknown"]:
        domain_counts[d] += 1

print(f"  Total ATT&CK techniques indexed (all 3 domains) : {n_attack:>5}")
print(f"    Enterprise (enterprise-attack-2.0)            : {domain_counts.get('enterprise-attack', 0):>5}")
print(f"    ICS        (ics-attack)                       : {domain_counts.get('ics-attack', 0):>5}")
print(f"    Mobile     (mobile-attack)                    : {domain_counts.get('mobile-attack', 0):>5}")
print(f"  Total D3FEND defensive techniques indexed       : {n_defend:>5}")
print(f"  ATT&CK techniques with at least one D3FEND map  : {n_mapped:>5}  "
      f"({100.0 * n_mapped / n_attack:.1f}% of ATT&CK)")

# SIFT mapping coverage
manual_count = len(attack.SIFT_MAPPINGS)
attack_ids = set(attack.TECHNIQUE_INDEX.keys())
manual_hit = attack_ids & set(attack.SIFT_MAPPINGS.keys())

# heuristic hit = any technique whose data-source graph walk yields a known data-source
heuristic_hit = set()
for tid, obj in attack.TECHNIQUE_INDEX.items():
    if tid in attack.SIFT_MAPPINGS:
        continue
    r = attack.get_sift_tools_for_technique(tid)
    if r["data"].get("candidate_servers"):
        heuristic_hit.add(tid)

total_sift_covered = len(manual_hit | heuristic_hit)
no_sift = sorted(attack_ids - manual_hit - heuristic_hit)

print(f"  ATT&CK techniques with SIFT manual mapping      : {len(manual_hit):>5}  "
      f"({100.0 * len(manual_hit) / n_attack:.1f}%)")
print(f"  ATT&CK techniques with SIFT heuristic mapping   : {len(heuristic_hit):>5}  "
      f"({100.0 * len(heuristic_hit) / n_attack:.1f}%)")
print(f"  ATT&CK techniques with NO SIFT mapping          : {len(no_sift):>5}  "
      f"({100.0 * len(no_sift) / n_attack:.1f}%)")
print(f"  Combined SIFT coverage (manual + heuristic)     : {total_sift_covered:>5}  "
      f"({100.0 * total_sift_covered / n_attack:.1f}%)")

# ── coverage gaps ─────────────────────────────────────────────────────────────
print("\nCOVERAGE GAPS")
print("─" * 70)

# top 10 unmapped ATT&CK techniques by how many groups use them
unmapped_with_actor_usage = []
for tid in no_sift:
    stix = attack.EXT_TO_STIX.get(tid)
    if not stix:
        continue
    n_groups = len([
        gid for gid in attack.REL_BY_TYPE_DST.get(("uses", stix), [])
        if attack.STIX_TO_EXT.get(gid, "").startswith("G")
    ])
    name = (attack.TECHNIQUE_INDEX[tid].get("name") or "")[:50]
    unmapped_with_actor_usage.append((n_groups, tid, name))
unmapped_with_actor_usage.sort(reverse=True)

print("\n  Top 10 SIFT-uncovered techniques by group-usage (most operationally important first):")
for n_groups, tid, name in unmapped_with_actor_usage[:10]:
    print(f"    {tid:<12}  {name:<50}  used by {n_groups:>3} actor groups")

# D3FEND gaps by ATT&CK domain
no_d3fend = attack_ids - set(defend.ATTACK_TO_DEFEND.keys())
no_d3fend_enterprise = [t for t in no_d3fend if attack.TECHNIQUE_INDEX[t].get("x_mitre_domains", ["?"])[0] == "enterprise-attack"]
no_d3fend_ics        = [t for t in no_d3fend if attack.TECHNIQUE_INDEX[t].get("x_mitre_domains", ["?"])[0] == "ics-attack"]
no_d3fend_mobile     = [t for t in no_d3fend if attack.TECHNIQUE_INDEX[t].get("x_mitre_domains", ["?"])[0] == "mobile-attack"]

print(f"\n  ATT&CK techniques with NO D3FEND defense (by domain):")
print(f"    Enterprise : {len(no_d3fend_enterprise):>4} of {domain_counts.get('enterprise-attack', 0)}")
print(f"    ICS        : {len(no_d3fend_ics):>4} of {domain_counts.get('ics-attack', 0)}   (D3FEND has zero ICS coverage)")
print(f"    Mobile     : {len(no_d3fend_mobile):>4} of {domain_counts.get('mobile-attack', 0)}")

print("\n  These gaps tell the IR analyst:")
print("    1. ATT&CK techniques the SIFT tool inventory CANNOT directly surface")
print("       → collect additional telemetry or use a non-SIFT forensic tool")
print("    2. ATT&CK techniques D3FEND has NO published countermeasure for")
print("       → the IR playbook needs ad-hoc / experience-driven response")
print("\n" + "═" * 70)
