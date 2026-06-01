import sys, importlib.util
sys.path.insert(0, "servers")
spec = importlib.util.spec_from_file_location("sift_attack", "servers/sift_attack.py")
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
print()

# 4 techniques NOT in hand-curated SIFT_MAPPINGS — proves dynamic path
samples = ["T1216", "T1497.001", "T1567.003", "T0855", "T1564.001", "T1574.013"]
for tid in samples:
    if tid not in a.TECHNIQUE_INDEX:
        print(f"{tid}: not in index")
        continue
    name = a.TECHNIQUE_INDEX[tid].get("name", "")[:50]
    in_manual = tid in a.SIFT_MAPPINGS
    r = a.get_sift_tools_for_technique(tid)
    d = r["data"]
    print(f"{tid}  ({name})")
    print(f"   in SIFT_MAPPINGS?  {in_manual}")
    print(f"   mapping_source  : {d['mapping_source']}")
    print(f"   data_sources    : {d.get('data_sources', [])[:6]}")
    print(f"   candidate_srvs  : {d.get('candidate_servers')}")
    print()
