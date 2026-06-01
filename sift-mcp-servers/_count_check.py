"""Honest count of what's in the source files vs what made it into TECHNIQUE_INDEX."""
import json
from collections import defaultdict

ROOT = "/mnt/c/Users/FlemingJohn/Downloads/sift-mcp-servers/repoistory-reference/attack-stix-data"
files = {
    "enterprise": f"{ROOT}/enterprise-attack/enterprise-attack.json",
    "ics":        f"{ROOT}/ics-attack/ics-attack.json",
    "mobile":     f"{ROOT}/mobile-attack/mobile-attack.json",
}

per_domain_raw = {}
per_domain_active = {}
per_domain_external_ids = {}
all_external_ids: dict[str, list[str]] = defaultdict(list)

for dom, path in files.items():
    data = json.load(open(path))
    raw = [o for o in data["objects"] if o["type"] == "attack-pattern"]
    active = [o for o in raw if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    per_domain_raw[dom] = len(raw)
    per_domain_active[dom] = len(active)
    ext_ids = set()
    for o in active:
        for r in o.get("external_references", []) or []:
            if r.get("source_name") == "mitre-attack":
                ext_id = r.get("external_id")
                if ext_id:
                    ext_ids.add(ext_id)
                    all_external_ids[ext_id].append(dom)
    per_domain_external_ids[dom] = ext_ids

# How many unique external IDs across all 3 domains?
unique_ext_ids = set(all_external_ids.keys())

print("─── raw attack-pattern objects in each file ───")
for dom in files:
    print(f"  {dom:<12} {per_domain_raw[dom]:>4} raw  →  {per_domain_active[dom]:>4} active  →  {len(per_domain_external_ids[dom]):>4} with external_id")
print(f"  {'TOTAL':<12} {sum(per_domain_raw.values()):>4} raw  →  {sum(per_domain_active.values()):>4} active  →  {sum(len(s) for s in per_domain_external_ids.values()):>4} with-id")
print()

# cross-domain duplicates
dups = {k: v for k, v in all_external_ids.items() if len(v) > 1}
print(f"─── cross-domain duplicates (same Txxxx ID in >1 bundle) ───")
print(f"  {len(dups)} technique IDs appear in multiple bundles")
print(f"  example IDs (first 10):")
for k in sorted(dups)[:10]:
    print(f"    {k:<10}  appears in: {dups[k]}")

print()
print("─── final answer ───")
print(f"  unique technique IDs across all 3 domains : {len(unique_ext_ids)}")
print(f"  → this is what TECHNIQUE_INDEX holds (1,140)")
print()
print(f"  raw attack-pattern records seen          : {sum(per_domain_raw.values())}")
print(f"  active (non-revoked, non-deprecated)     : {sum(per_domain_active.values())}")
print(f"  with valid MITRE external_id             : {sum(len(s) for s in per_domain_external_ids.values())}")
print(f"  unique after dedup across domains        : {len(unique_ext_ids)}")
print(f"  dropped from raw → indexed               : {sum(per_domain_raw.values()) - len(unique_ext_ids)}")
print()
print(f"  causes of difference:")
print(f"    - revoked / deprecated   : {sum(per_domain_raw.values()) - sum(per_domain_active.values())}")
print(f"    - cross-domain duplicates: {sum(per_domain_active.values()) - len(unique_ext_ids)}")
