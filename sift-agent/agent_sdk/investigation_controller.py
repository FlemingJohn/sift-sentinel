import json

from case_state import (
    add_attack_techniques,
    add_candidate_files,
    add_defenses,
    add_finding,
    apply_evidence_classification,
    apply_evidence_hashes,
    create_initial_case_state,
    evidence_hash_set,
    hashed_evidence_paths,
)
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
from text_parsing import parse_first_json


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


def parse_rows(result, container_key):
    parsed = parse_first_json(result.final_text)
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
    paths = [
        evidence_record.path
        for evidence_record in case_state.evidence
        if not evidence_record.sha256
    ]
    task_text = f"Hash these files and return the JSON manifest: {json.dumps(paths)}"
    result = await run_specialist(configuration, task_text, case_state, audit_logger)
    audit_logger.specialist_completed(
        configuration.name, result.input_tokens, result.output_tokens,
        result.cost_usd, configuration.is_supervisor,
    )

    hash_by_path = {}
    for row in parse_rows(result, "hashes"):
        if isinstance(row, dict) and row.get("path"):
            hash_by_path[row["path"]] = row

    chain_entries = build_chain_entries("hasher", result.tool_envelopes)
    for path, row in hash_by_path.items():
        apply_evidence_hashes(
            case_state, path,
            row.get("sha256") or "",
            row.get("md5") or "",
            row.get("ssdeep") or "",
            chain_entries,
        )


async def run_analysis_specialist(case_state, specialist_name, audit_logger):
    configuration = SPECIALIST_DEFINITIONS[specialist_name]
    audit_logger.specialist_started(configuration.name, configuration.description)
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
    task_text = " ".join(task_lines)
    result = await run_specialist(configuration, task_text, case_state, audit_logger)
    audit_logger.specialist_completed(
        configuration.name, result.input_tokens, result.output_tokens,
        result.cost_usd, configuration.is_supervisor,
    )

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


async def run_attribute_phase(case_state, audit_logger):
    audit_logger.phase_changed("attribute")
    attack_configuration = SPECIALIST_DEFINITIONS["attack_map"]
    pending_findings = [
        finding_record for finding_record in case_state.findings
        if not finding_record.attack_techniques
    ]
    if pending_findings:
        audit_logger.specialist_started(
            attack_configuration.name, attack_configuration.description
        )
        items = [
            {"id": finding_record.identifier, "claim": finding_record.claim}
            for finding_record in pending_findings
        ]
        task_text = f"Map these findings to ATT&CK:\n{json.dumps(items, indent=2)}"
        result = await run_specialist(
            attack_configuration, task_text, case_state, audit_logger
        )
        audit_logger.specialist_completed(
            attack_configuration.name, result.input_tokens, result.output_tokens,
            result.cost_usd, attack_configuration.is_supervisor,
        )
        for row in parse_rows(result, "patches"):
            if isinstance(row, dict) and row.get("id") and row.get("attack_techniques"):
                add_attack_techniques(case_state, row["id"], row["attack_techniques"])

    defense_configuration = SPECIALIST_DEFINITIONS["defense_map"]
    mapped_findings = [
        finding_record for finding_record in case_state.findings
        if finding_record.attack_techniques and not finding_record.d3fend_defenses
    ]
    if mapped_findings:
        audit_logger.specialist_started(
            defense_configuration.name, defense_configuration.description
        )
        items = [
            {
                "id": finding_record.identifier,
                "attack_techniques": finding_record.attack_techniques,
            }
            for finding_record in mapped_findings
        ]
        task_text = f"Map these findings to D3FEND:\n{json.dumps(items, indent=2)}"
        result = await run_specialist(
            defense_configuration, task_text, case_state, audit_logger
        )
        audit_logger.specialist_completed(
            defense_configuration.name, result.input_tokens, result.output_tokens,
            result.cost_usd, defense_configuration.is_supervisor,
        )
        for row in parse_rows(result, "patches"):
            if isinstance(row, dict) and row.get("id") and row.get("d3fend_defenses"):
                add_defenses(case_state, row["id"], row["d3fend_defenses"])


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


async def run_investigation(case_id, evidence_paths, audit_logger):
    case_state = create_initial_case_state(case_id, evidence_paths)
    audit_logger.open_case(case_id)

    if not case_state.evidence:
        case_state.halt_reason = "no_evidence"
        halt_investigation(case_state, audit_logger)
        audit_logger.close_case()
        audit_logger.print_summary()
        return case_state

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
