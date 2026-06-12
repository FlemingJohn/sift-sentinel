from case_state import (
    add_attack_techniques,
    add_candidate_files,
    add_defenses,
    add_finding,
    apply_evidence_classification,
    apply_evidence_hashes,
    create_initial_case_state,
    evidence_hash_set,
)
from forensic_records import build_finding
from gates import (
    determine_halt_reason,
    evidence_is_fully_hashed,
    findings_have_attribution,
)
from mcp_servers import (
    qualified_tool_names,
    server_file_name,
    servers_for_tools,
    unqualified_tool_name,
)
from routing import select_specialists
from specialist_tools import SPECIALIST_TOOL_ALLOWLISTS
from text_parsing import parse_first_json
from tool_server_map import TOOL_SERVER_NAMES


passed = 0
failed = 0


def check(description, condition):
    global passed, failed
    if condition:
        passed += 1
        print(f"PASS {description}")
    else:
        failed += 1
        print(f"FAIL {description}")


def case_with_disk_image():
    case_state = create_initial_case_state("case-1", ["/evidence/disk.E01"])
    apply_evidence_classification(case_state, "/evidence/disk.E01", "disk", 100, "")
    case_state.has_disk_image = True
    return case_state


check(
    "initial state has one evidence record",
    len(create_initial_case_state("c", ["/a"]).evidence) == 1,
)

check(
    "evidence is not hashed initially",
    not evidence_is_fully_hashed(create_initial_case_state("c", ["/a"])),
)

hashed_case = create_initial_case_state("c", ["/a"])
apply_evidence_hashes(hashed_case, "/a", "abc123", "md5val", "ssdeepval", [])
check("evidence becomes hashed after applying sha256", evidence_is_fully_hashed(hashed_case))
check("hash set contains the sha256", evidence_hash_set(hashed_case) == {"abc123"})

empty_case = create_initial_case_state("c", [])
check("empty evidence fails hash gate", not evidence_is_fully_hashed(empty_case))
check("empty evidence halt reason is no_evidence", determine_halt_reason(empty_case) == "no_evidence")

unhashed_case = create_initial_case_state("c", ["/a"])
check(
    "unhashed evidence halt reason is unhashed_evidence",
    determine_halt_reason(unhashed_case) == "unhashed_evidence",
)

check(
    "disk image routes to filesystem and carver",
    select_specialists(case_with_disk_image()) == ["filesystem", "carver"],
)

memory_case = create_initial_case_state("c", ["/m"])
memory_case.has_memory_dump = True
check("memory dump routes to memory", "memory" in select_specialists(memory_case))

pcap_case = create_initial_case_state("c", ["/p"])
pcap_case.has_pcap = True
check("pcap routes to network", "network" in select_specialists(pcap_case))

candidate_case = case_with_disk_image()
add_candidate_files(candidate_case, ["/image/evil.exe"])
selection = select_specialists(candidate_case)
check("candidate files route to malware_static", "malware_static" in selection)
check("candidate files route to reversing", "reversing" in selection)

empty_routing_case = create_initial_case_state("c", ["/x"])
check(
    "no evidence flags defaults to filesystem",
    select_specialists(empty_routing_case) == ["filesystem"],
)

routing_has_no_duplicates = case_with_disk_image()
add_candidate_files(routing_has_no_duplicates, ["/image/evil.exe"])
result = select_specialists(routing_has_no_duplicates)
check("routing has no duplicate specialists", len(result) == len(set(result)))

attribution_case = create_initial_case_state("c", ["/a"])
apply_evidence_hashes(attribution_case, "/a", "abc123", "", "", [])
finding = build_finding("filesystem", "suspicious binary", ["abc123"], [], "weak")
add_finding(attribution_case, finding)
check("findings without attribution fail gate", not findings_have_attribution(attribution_case))
add_attack_techniques(attribution_case, finding.identifier, ["T1059.001"])
check("findings with attribution pass gate", findings_have_attribution(attribution_case))
check(
    "attribution halt reason when missing",
    determine_halt_reason(create_initial_case_state("c", ["/a"])) == "unhashed_evidence",
)

add_defenses(attribution_case, finding.identifier, ["D3-AMED"])
check("defenses are added to finding", attribution_case.findings[0].d3fend_defenses == ["D3-AMED"])

check("every specialist has a non empty tool allowlist",
      all(len(tool_names) > 0 for tool_names in SPECIALIST_TOOL_ALLOWLISTS.values()))

check("hasher tools are all in hashing server",
      all(TOOL_SERVER_NAMES.get(name) == "sift-hashing"
          for name in SPECIALIST_TOOL_ALLOWLISTS["hasher"]))

check("attack map tools have no tool_ prefix",
      all(not name.startswith("tool_") for name in SPECIALIST_TOOL_ALLOWLISTS["attack_map"]))

check("server file name maps hyphen to underscore",
      server_file_name("sift-disk") == "sift_disk.py")

check("qualified tool names are namespaced",
      qualified_tool_names(["tool_fls"]) == ["mcp__sift-disk__tool_fls"])

check("unqualified tool name strips namespace",
      unqualified_tool_name("mcp__sift-disk__tool_fls") == "tool_fls")

check("filesystem tools resolve to a single server",
      servers_for_tools(SPECIALIST_TOOL_ALLOWLISTS["filesystem"]) == ["sift-disk"])

KNOWN_UNREGISTERED_TOOLS = {"tool_dd"}

unresolved_tools = {
    name
    for tool_names in SPECIALIST_TOOL_ALLOWLISTS.values()
    for name in tool_names
    if name not in TOOL_SERVER_NAMES
}
check("only known unregistered tools fail to resolve",
      unresolved_tools == KNOWN_UNREGISTERED_TOOLS)

check("parse_first_json reads an embedded object",
      parse_first_json('text {"a": 1} trailing') == {"a": 1})

check("parse_first_json returns none on no json",
      parse_first_json("no json here") is None)

check("malware static never includes execution tools",
      all("wine" not in name for name in SPECIALIST_TOOL_ALLOWLISTS["malware_static"]))

print(f"\npassed={passed} failed={failed}")
if failed:
    raise SystemExit(1)
