import sys, importlib.util
sys.path.insert(0, "servers")
spec = importlib.util.spec_from_file_location("sift_attack", "servers/sift_attack.py")
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
print()

for tid in ["T1548.001", "T1547.004", "T1547.014", "T1059.005", "T1204.002"]:
    if tid not in a.TECHNIQUE_INDEX:
        print(f"{tid}: NOT IN INDEX")
        continue
    stix = a.EXT_TO_STIX.get(tid)
    ds_list = a.REL_BY_TYPE_DST.get(("detects", stix), [])
    print(f"{tid}: stix={stix[:36]}  detection-strategies={len(ds_list)}")
    for ds_stix in ds_list[:2]:
        strat = a.DETSTRAT_INDEX.get(ds_stix)
        if not strat:
            print(f"  MISSING strategy {ds_stix[:40]}")
            continue
        name = (strat.get("name") or "")[:60]
        an_refs = strat.get("x_mitre_analytic_refs") or []
        print(f"  strat={name}  analytics={len(an_refs)}")
        for an_stix in an_refs[:2]:
            an = a.ANALYTIC_INDEX.get(an_stix)
            if not an:
                print(f"    MISSING analytic {an_stix[:40]}")
                continue
            log_refs = an.get("x_mitre_log_source_references") or []
            print(f"    analytic log_refs={len(log_refs)}")
            for lr in log_refs[:2]:
                comp_id = lr.get("x_mitre_data_component_ref")
                comp = a.DATACOMP_INDEX.get(comp_id)
                if not comp:
                    print(f"      MISSING component {comp_id}")
                    continue
                src_id = comp.get("x_mitre_data_source_ref")
                src = a.DATASRC_INDEX.get(src_id)
                comp_name = comp.get("name")
                src_name = src.get("name") if src else None
                print(f"      component={comp_name}  → datasource={src_name}")
    r = a.get_sift_tools_for_technique(tid)
    ds_found = r["data"].get("data_sources")
    cs_found = r["data"].get("candidate_servers")
    print(f"  → tool result: data_sources={ds_found}  candidate_servers={cs_found}")
    print()
