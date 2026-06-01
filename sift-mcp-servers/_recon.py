"""Expanded recon — all 3 ATT&CK domains + deeper D3FEND structure."""
import json, time, zipfile, re
from collections import Counter, defaultdict

ATTACK_ROOT = "/mnt/c/Users/FlemingJohn/Downloads/sift-mcp-servers/repoistory-reference/attack-stix-data"
D3F_ZIP     = "/mnt/c/Users/FlemingJohn/Downloads/sift-mcp-servers/repoistory-reference/d3fend-gh-pages.zip"

# ── ATT&CK across all 3 domains ───────────────────────────────────────────────
print("═" * 70)
print("  ATT&CK — all domains")
print("═" * 70)

domains = {
    "enterprise": f"{ATTACK_ROOT}/enterprise-attack/enterprise-attack.json",
    "ics":        f"{ATTACK_ROOT}/ics-attack/ics-attack.json",
    "mobile":     f"{ATTACK_ROOT}/mobile-attack/mobile-attack.json",
}

domain_stats = {}
for dom, path in domains.items():
    t0 = time.time()
    data = json.load(open(path))
    dur = time.time() - t0
    objs = data["objects"]
    types = Counter(o["type"] for o in objs)
    techs = [o for o in objs if o["type"] == "attack-pattern"]
    # technique counts (split top-level vs sub-techniques)
    top_level = sum(1 for t in techs if not t.get("x_mitre_is_subtechnique"))
    sub_tech  = sum(1 for t in techs if t.get("x_mitre_is_subtechnique"))
    # platforms
    platforms = Counter()
    for t in techs:
        for p in t.get("x_mitre_platforms", []) or []:
            platforms[p] += 1
    # tactics
    tactics = Counter()
    for t in techs:
        for kc in t.get("kill_chain_phases", []) or []:
            tactics[kc["phase_name"]] += 1

    domain_stats[dom] = {
        "load_s":     round(dur, 2),
        "objects":    len(objs),
        "techniques": len(techs),
        "top_level":  top_level,
        "sub_tech":   sub_tech,
        "groups":     types.get("intrusion-set", 0),
        "software":   types.get("malware", 0) + types.get("tool", 0),
        "campaigns":  types.get("campaign", 0),
        "mitigations":types.get("course-of-action", 0),
        "relationships": types.get("relationship", 0),
        "tactics":    dict(tactics),
        "top_platforms": dict(platforms.most_common(5)),
        "types":      dict(types),
    }
    print(f"\n  {dom.upper():<10} ({path.split('/')[-1]})")
    print(f"    load        : {dur:.2f}s")
    print(f"    objects     : {len(objs):,}")
    print(f"    techniques  : {len(techs):,}  ({top_level} top-level + {sub_tech} sub)")
    print(f"    groups      : {types.get('intrusion-set', 0):,}")
    print(f"    software    : {types.get('malware', 0) + types.get('tool', 0):,}  (malware + tool)")
    print(f"    mitigations : {types.get('course-of-action', 0):,}")
    print(f"    relationships: {types.get('relationship', 0):,}")
    print(f"    tactics     : {list(tactics.keys())}")
    print(f"    platforms   : {dict(platforms.most_common(6))}")

print(f"\n  ── ATT&CK GRAND TOTAL (all 3 domains) ──")
g_obj = sum(d["objects"] for d in domain_stats.values())
g_tech= sum(d["techniques"] for d in domain_stats.values())
g_grp = sum(d["groups"] for d in domain_stats.values())
g_sw  = sum(d["software"] for d in domain_stats.values())
g_mit = sum(d["mitigations"] for d in domain_stats.values())
print(f"    objects     : {g_obj:,}")
print(f"    techniques  : {g_tech:,}   (cross-domain duplicates possible)")
print(f"    groups      : {g_grp:,}    (heavy overlap — same groups appear in all 3)")
print(f"    software    : {g_sw:,}")
print(f"    mitigations : {g_mit:,}")

# ── D3FEND deeper look ────────────────────────────────────────────────────────
print()
print("═" * 70)
print("  D3FEND — deeper")
print("═" * 70)

z = zipfile.ZipFile(D3F_ZIP)

# How many per-technique offensive-technique files? per-defensive-technique?
def count_dir(prefix):
    return sum(1 for n in z.namelist() if n.startswith(prefix) and n.endswith(".json"))

print(f"\n  api/offensive-technique/attack/*.json : {count_dir('d3fend-gh-pages/api/offensive-technique/attack/')}")
print(f"  api/technique/*.json                   : {count_dir('d3fend-gh-pages/api/technique/')}")
print(f"  api/artifact/*.json                    : {count_dir('d3fend-gh-pages/api/artifact/')}")
print(f"  api/tactic/*.json                      : {count_dir('d3fend-gh-pages/api/tactic/')}")
print(f"  api/digital-artifact/*.json            : {count_dir('d3fend-gh-pages/api/digital-artifact/')}")

# Pull all distinct D3FEND defensive technique IDs (D3-XXX) from the OWL file
t0 = time.time()
with z.open("d3fend-gh-pages/ontologies/d3fend.owl") as f:
    owl = f.read().decode("utf-8", errors="replace")
print(f"\n  d3fend.owl load: {time.time()-t0:.2f}s, {len(owl):,} bytes")

# D3FEND IDs look like "d3f:D3-SBL" or "rdf:about=\"http://...#D3-SBL\""
d3_ids = set(re.findall(r"#(D3-[A-Z0-9]{2,8})", owl))
print(f"  distinct D3-XXX IDs in OWL : {len(d3_ids):,}")
print(f"  sample (first 20)          : {sorted(d3_ids)[:20]}")

# Tactics in D3FEND (Harden/Detect/Isolate/Deceive/Evict/Restore + new ones)
tactics = set(re.findall(r"d3fend:(Harden|Detect|Isolate|Deceive|Evict|Restore|Model)", owl))
print(f"  D3FEND tactics found       : {sorted(tactics)}")

# Mappings file: which ATT&CK techniques have D3FEND coverage?
print(f"\n  Loading d3fend-full-mappings.json...")
t0 = time.time()
with z.open("d3fend-gh-pages/api/ontology/inference/d3fend-full-mappings.json") as f:
    mp = json.load(f)
print(f"    load : {time.time()-t0:.2f}s")
rows = mp["results"]["bindings"]
print(f"    rows : {len(rows):,}")

mapped_attack_ids = set()
def_techs_per_attack = defaultdict(set)
for r in rows:
    aid = r.get("off_tech_id", {}).get("value")
    dt  = r.get("def_tech_label", {}).get("value")
    if aid:
        mapped_attack_ids.add(aid)
        if dt:
            def_techs_per_attack[aid].add(dt)

print(f"    unique ATT&CK technique IDs covered : {len(mapped_attack_ids):,}")
print(f"    ATT&CK IDs by domain prefix:")
# All ATT&CK IDs start with T; ICS uses T0xxx, Mobile uses T1xxx (overlapping), Enterprise T1xxx
ranges = Counter()
for aid in mapped_attack_ids:
    if aid.startswith("T0"):
        ranges["T0xxx (ICS)"] += 1
    elif aid.startswith("T1"):
        ranges["T1xxx (Enterprise/Mobile)"] += 1
    else:
        ranges["other"] += 1
for k, v in ranges.items():
    print(f"      {k:<32} {v}")

# Avg D3FEND techniques per ATT&CK technique
avg = sum(len(s) for s in def_techs_per_attack.values()) / max(1, len(def_techs_per_attack))
print(f"    avg D3FEND techs per ATT&CK ID : {avg:.1f}")

# Save a compact mapping for inspection
print()
print("  Sample mapping: T1059.001 PowerShell →")
for dt in sorted(def_techs_per_attack.get("T1059.001", set())):
    print(f"    - {dt}")
