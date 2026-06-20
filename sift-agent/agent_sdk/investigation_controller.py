import asyncio
import json
from pathlib import PurePosixPath

from configuration import MAXIMUM_ANALYSIS_ATTEMPTS, WSL_DISTRIBUTION

from case_state import (
    add_attack_techniques,
    add_candidate_files,
    add_defenses,
    add_finding,
    apply_evidence_classification,
    create_initial_case_state,
    evidence_hash_set,
    find_finding_by_identifier,
    hashed_evidence_paths,
)
from deterministic_hashing import compute_evidence_hashes
from forensic_records import build_chain_entries, build_finding
from gates import (
    determine_halt_reason,
    evidence_is_fully_hashed,
    findings_have_attribution,
)
from report_synthesizer import generate_narrative, validate_findings, write_report
from routing import select_specialists
from specialist_runner import run_specialist
from specialists import SPECIALIST_DEFINITIONS
from technique_corpus import filter_valid_techniques, load_valid_technique_ids
from text_parsing import parse_json_with_key


DISK_EXTENSIONS = (".e01", ".aff", ".dd", ".raw", ".img", ".001", ".ad1")
MEMORY_EXTENSIONS = (".mem", ".vmem", ".dmp", ".lime", ".raw_mem")
PCAP_EXTENSIONS = (".pcap", ".pcapng", ".cap")


def classify_by_extension(path):
    lowered = path.lower()
    if lowered.endswith(DISK_EXTENSIONS):
        return "disk"
    if lowered.endswith(MEMORY_EXTENSIONS):
        return "memory"
    if lowered.endswith(PCAP_EXTENSIONS):
        return "pcap"
    return "other"


ATTRIBUTION_MAPPING_PASSES = 2

EVIDENCE_LINK_DIRECTORY = "/var/tmp/sift-evidence"


async def run_wsl_command(*arguments):
    process = await asyncio.create_subprocess_exec(
        "wsl.exe", "-d", WSL_DISTRIBUTION, "--", *arguments,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.DEVNULL,
    )
    stdout_bytes, stderr_bytes = await process.communicate()
    return (
        process.returncode,
        stdout_bytes.decode("utf-8", "replace"),
        stderr_bytes.decode("utf-8", "replace").strip(),
    )


async def prepare_evidence_links(case_state, audit_logger):
    await run_wsl_command("mkdir", "-p", EVIDENCE_LINK_DIRECTORY)
    for evidence_record in case_state.evidence:
        link_path = f"{EVIDENCE_LINK_DIRECTORY}/{PurePosixPath(evidence_record.host_path).name}"
        returncode, _, stderr_text = await run_wsl_command(
            "ln", "-sf", evidence_record.host_path, link_path
        )
        if returncode == 0:
            evidence_record.path = link_path
        else:
            audit_logger.error_occurred(
                "prepare", f"space-free link failed for {evidence_record.host_path}: {stderr_text}"
            )


def parse_rows(result, container_key):
    parsed = parse_json_with_key(result.final_text, container_key)
    if not isinstance(parsed, dict):
        return []
    rows = parsed.get(container_key)
    return rows if isinstance(rows, list) else []


async def run_acquire_phase(case_state, audit_logger):
    audit_logger.phase_changed("acquire")
    configuration = SPECIALIST_DEFINITIONS["acquirer"]
    audit_logger.specialist_started(configuration.name, configuration.description)
    paths = [evidence_record.path for evidence_record in case_state.evidence]
    task_text = (
        "Identify and characterise these evidence files. Return one JSON object "
        f"as specified. Files: {json.dumps(paths)}"
    )
    result = await run_specialist(configuration, task_text, case_state, audit_logger)
    audit_logger.specialist_completed(
        configuration.name, result.input_tokens, result.output_tokens,
        result.cost_usd, configuration.is_supervisor,
    )

    classification_by_path = {}
    for row in parse_rows(result, "images"):
        if isinstance(row, dict) and row.get("path"):
            classification_by_path[row["path"]] = row

    chain_entries = build_chain_entries("acquirer", result.tool_envelopes)
    for evidence_record in case_state.evidence:
        classification = classification_by_path.get(evidence_record.path, {})
        evidence_type = classification.get("type") or classify_by_extension(evidence_record.path)
        apply_evidence_classification(
            case_state,
            evidence_record.path,
            evidence_type,
            classification.get("size_bytes") or 0,
            classification.get("mime") or "",
        )
        for chain_entry in chain_entries:
            evidence_record.chain_of_custody.append(chain_entry)
        if evidence_type == "disk":
            case_state.has_disk_image = True
        elif evidence_type == "memory":
            case_state.has_memory_dump = True
        elif evidence_type == "pcap":
            case_state.has_pcap = True


async def run_hash_phase(case_state, audit_logger):
    audit_logger.phase_changed("hash")
    configuration = SPECIALIST_DEFINITIONS["hasher"]
    audit_logger.specialist_started(configuration.name, configuration.description)
    for evidence_record in case_state.evidence:
        if evidence_record.sha256:
            continue
        hashes = await asyncio.to_thread(compute_evidence_hashes, evidence_record.host_path)
        evidence_record.sha256 = hashes["sha256"]
        evidence_record.md5 = hashes["md5"]
        evidence_record.sha1 = hashes["sha1"]
        envelope = {"tool": "hashlib", "exit_code": 0, **hashes}
        evidence_record.chain_of_custody.extend(build_chain_entries("hasher", [envelope]))
        audit_logger.tool_invoked("hasher", "hashlib", 0, None)
        audit_logger.information(
            "hasher",
            f"{PurePosixPath(evidence_record.host_path).name} "
            f"md5={hashes['md5']} sha1={hashes['sha1']} sha256={hashes['sha256']}",
        )
    audit_logger.specialist_completed(configuration.name, 0, 0, 0.0, configuration.is_supervisor)


def build_analysis_task(case_state):
    references = sorted(evidence_hash_set(case_state))
    evidence_paths = hashed_evidence_paths(case_state)
    task_lines = [
        "Analyse the hashed evidence for forensic findings.",
        f"Evidence files: {json.dumps(evidence_paths)}",
        f"Evidence hashes: {json.dumps(references)}",
    ]
    if case_state.candidate_files:
        task_lines.append(
            f"Candidate files of interest: {json.dumps(case_state.candidate_files)}"
        )
    return " ".join(task_lines)


def apply_specialist_findings(case_state, result, specialist_name, references):
    findings_added = 0
    for row in parse_rows(result, "findings"):
        if not isinstance(row, dict) or not row.get("claim"):
            continue
        finding_record = build_finding(
            produced_by=specialist_name,
            claim=row["claim"],
            evidence_references=references,
            tool_envelopes=result.tool_envelopes,
            confidence="weak",
        )
        add_finding(case_state, finding_record)
        candidate_files = row.get("candidate_files") or []
        add_candidate_files(case_state, candidate_files)
        findings_added += 1
    return findings_added


async def run_analysis_specialist(case_state, specialist_name, audit_logger):
    configuration = SPECIALIST_DEFINITIONS[specialist_name]
    references = sorted(evidence_hash_set(case_state))
    task_text = build_analysis_task(case_state)
    findings_added = 0
    for attempt in range(1, MAXIMUM_ANALYSIS_ATTEMPTS + 1):
        audit_logger.specialist_started(configuration.name, configuration.description)
        result = await run_specialist(configuration, task_text, case_state, audit_logger)
        audit_logger.specialist_completed(
            configuration.name, result.input_tokens, result.output_tokens,
            result.cost_usd, configuration.is_supervisor,
        )
        findings_added = apply_specialist_findings(
            case_state, result, specialist_name, references
        )
        if findings_added > 0:
            break
        if attempt < MAXIMUM_ANALYSIS_ATTEMPTS:
            audit_logger.information(
                specialist_name,
                f"no findings on attempt {attempt} of {MAXIMUM_ANALYSIS_ATTEMPTS}; retrying",
            )
    return findings_added


async def run_analyze_phase(case_state, audit_logger):
    audit_logger.phase_changed("analyze")
    executed = set()
    while True:
        selection = select_specialists(case_state)
        pending = [name for name in selection if name not in executed]
        if not pending:
            break
        for specialist_name in pending:
            await run_analysis_specialist(case_state, specialist_name, audit_logger)
            executed.add(specialist_name)


def build_ordinal_mapping(findings):
    ordinal_to_identifier = {}
    for position, finding_record in enumerate(findings, start=1):
        ordinal_to_identifier[str(position)] = finding_record.identifier
    return ordinal_to_identifier


async def run_attack_mapping_pass(case_state, findings, valid_technique_ids, audit_logger):
    configuration = SPECIALIST_DEFINITIONS["attack_map"]
    audit_logger.specialist_started(configuration.name, configuration.description)
    ordinal_to_identifier = build_ordinal_mapping(findings)
    items = [
        {"id": ordinal, "claim": find_finding_by_identifier(case_state, identifier).claim}
        for ordinal, identifier in ordinal_to_identifier.items()
    ]
    task_text = f"Map these findings to ATT&CK:\n{json.dumps(items, indent=2)}"
    result = await run_specialist(configuration, task_text, case_state, audit_logger)
    audit_logger.specialist_completed(
        configuration.name, result.input_tokens, result.output_tokens,
        result.cost_usd, configuration.is_supervisor,
    )
    for row in parse_rows(result, "patches"):
        if not isinstance(row, dict):
            continue
        identifier = ordinal_to_identifier.get(str(row.get("id")))
        techniques = row.get("attack_techniques")
        if not identifier or not techniques:
            continue
        accepted, rejected = filter_valid_techniques(techniques, valid_technique_ids)
        if rejected:
            audit_logger.information(
                "attack_map",
                f"rejected uncorroborated technique ids for {identifier}: "
                f"{', '.join(rejected)}",
            )
        if accepted:
            add_attack_techniques(case_state, identifier, accepted)


async def run_defense_mapping_pass(case_state, findings, audit_logger):
    configuration = SPECIALIST_DEFINITIONS["defense_map"]
    audit_logger.specialist_started(configuration.name, configuration.description)
    ordinal_to_identifier = build_ordinal_mapping(findings)
    items = [
        {
            "id": ordinal,
            "attack_techniques": find_finding_by_identifier(
                case_state, identifier
            ).attack_techniques,
        }
        for ordinal, identifier in ordinal_to_identifier.items()
    ]
    task_text = f"Map these findings to D3FEND:\n{json.dumps(items, indent=2)}"
    result = await run_specialist(configuration, task_text, case_state, audit_logger)
    audit_logger.specialist_completed(
        configuration.name, result.input_tokens, result.output_tokens,
        result.cost_usd, configuration.is_supervisor,
    )
    for row in parse_rows(result, "patches"):
        if not isinstance(row, dict):
            continue
        identifier = ordinal_to_identifier.get(str(row.get("id")))
        defenses = row.get("d3fend_defenses")
        if identifier and defenses:
            add_defenses(case_state, identifier, defenses)


async def run_attribute_phase(case_state, audit_logger):
    audit_logger.phase_changed("attribute")
    valid_technique_ids = load_valid_technique_ids()
    if not valid_technique_ids:
        case_state.halt_reason = "attack_corpus_unavailable"
        audit_logger.error_occurred(
            "attribute",
            "ATT&CK corpus could not be loaded; cannot validate attribution",
        )
        return

    for _ in range(ATTRIBUTION_MAPPING_PASSES):
        unattributed = [
            finding_record for finding_record in case_state.findings
            if not finding_record.attack_techniques
        ]
        if not unattributed:
            break
        await run_attack_mapping_pass(
            case_state, unattributed, valid_technique_ids, audit_logger
        )

    mapped_findings = [
        finding_record for finding_record in case_state.findings
        if finding_record.attack_techniques and not finding_record.d3fend_defenses
    ]
    if mapped_findings:
        await run_defense_mapping_pass(case_state, mapped_findings, audit_logger)


async def run_report_phase(case_state, audit_logger):
    audit_logger.phase_changed("report")
    accepted_findings, dropped_findings = validate_findings(case_state)
    summary = await generate_narrative(case_state, accepted_findings)
    output_path = write_report(case_state, summary, accepted_findings, dropped_findings)
    case_state.phase = "done"
    audit_logger.information("synthesizer", f"report written to {output_path}")


def halt_investigation(case_state, audit_logger):
    case_state.halted = True
    case_state.phase = "halted"
    case_state.halt_reason = determine_halt_reason(case_state)
    audit_logger.error_occurred("halt", f"reason={case_state.halt_reason}")


async def run_investigation(case_id, evidence_paths, audit_logger, on_case_state=None):
    case_state = create_initial_case_state(case_id, evidence_paths)
    if on_case_state is not None:
        on_case_state(case_state)
    audit_logger.open_case(case_id)

    if not case_state.evidence:
        case_state.halt_reason = "no_evidence"
        halt_investigation(case_state, audit_logger)
        audit_logger.close_case()
        audit_logger.print_summary()
        return case_state

    await prepare_evidence_links(case_state, audit_logger)
    await run_acquire_phase(case_state, audit_logger)
    await run_hash_phase(case_state, audit_logger)

    if not evidence_is_fully_hashed(case_state):
        audit_logger.gate_evaluated("hash_ok", "fail")
        halt_investigation(case_state, audit_logger)
        audit_logger.close_case()
        audit_logger.print_summary()
        return case_state
    audit_logger.gate_evaluated("hash_ok", "ok")

    await run_analyze_phase(case_state, audit_logger)
    await run_attribute_phase(case_state, audit_logger)

    if not findings_have_attribution(case_state):
        audit_logger.gate_evaluated("attribution_ok", "fail")
        halt_investigation(case_state, audit_logger)
        audit_logger.close_case()
        audit_logger.print_summary()
        return case_state
    audit_logger.gate_evaluated("attribution_ok", "ok")

    await run_report_phase(case_state, audit_logger)
    audit_logger.close_case()
    audit_logger.print_summary()
    return case_state
