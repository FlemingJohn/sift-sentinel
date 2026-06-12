import json
import os
from dataclasses import asdict, dataclass, field

from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query

from case_state import evidence_hash_set
from configuration import REPORTS_DIRECTORY, SUPERVISOR_MODEL_NAME


NARRATIVE_PROMPT = (
    "You are the report synthesizer for a forensic investigation. Using only the "
    "validated findings provided, write a five sentence narrative summary describing "
    "what happened, the ATT&CK techniques observed, and the recommended D3FEND "
    "defenses. Do not invent any indicator or technique that is not present in the "
    "findings."
)


@dataclass
class DroppedFinding:
    identifier: str
    reason: str


@dataclass
class ForensicReport:
    case_id: str
    summary: str
    findings: list = field(default_factory=list)
    dropped: list = field(default_factory=list)
    evidence_count: int = 0
    chain_of_custody_complete: bool = False


def validate_findings(case_state):
    known_hashes = evidence_hash_set(case_state)
    accepted = []
    dropped = []
    for finding_record in case_state.findings:
        references = finding_record.evidence_references or []
        if not references or not all(reference in known_hashes for reference in references):
            dropped.append(DroppedFinding(
                identifier=finding_record.identifier,
                reason="missing_or_unknown_evidence_reference",
            ))
            continue
        if not finding_record.attack_techniques:
            dropped.append(DroppedFinding(
                identifier=finding_record.identifier,
                reason="missing_attack_mapping",
            ))
            continue
        accepted.append(finding_record)
    return accepted, dropped


async def generate_narrative(case_state, accepted_findings):
    brief = [
        {
            "claim": finding_record.claim,
            "techniques": finding_record.attack_techniques,
            "defenses": finding_record.d3fend_defenses,
            "confidence": finding_record.confidence,
        }
        for finding_record in accepted_findings
    ]
    task_text = (
        f"Case: {case_state.case_id}\n"
        f"Validated findings:\n{json.dumps(brief, indent=2)}"
    )
    options = ClaudeAgentOptions(
        system_prompt=NARRATIVE_PROMPT,
        model=SUPERVISOR_MODEL_NAME,
        allowed_tools=[],
        permission_mode="dontAsk",
        setting_sources=[],
    )
    summary_text = ""
    async for message in query(prompt=task_text, options=options):
        if isinstance(message, ResultMessage) and message.result:
            summary_text = message.result
    if not summary_text:
        summary_text = (
            f"Forensic report for case {case_state.case_id}: "
            f"{len(accepted_findings)} validated findings."
        )
    return summary_text


def chain_of_custody_complete(case_state):
    if not case_state.evidence:
        return False
    return all(evidence_record.chain_of_custody for evidence_record in case_state.evidence)


def write_report(case_state, summary, accepted_findings, dropped_findings):
    report = ForensicReport(
        case_id=case_state.case_id,
        summary=summary,
        findings=[asdict(finding_record) for finding_record in accepted_findings],
        dropped=[asdict(dropped_finding) for dropped_finding in dropped_findings],
        evidence_count=len(case_state.evidence),
        chain_of_custody_complete=chain_of_custody_complete(case_state),
    )
    os.makedirs(REPORTS_DIRECTORY, exist_ok=True)
    output_path = os.path.join(REPORTS_DIRECTORY, f"{case_state.case_id}.json")
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(asdict(report), handle, indent=2)
    return output_path
