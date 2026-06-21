from dataclasses import dataclass, field


@dataclass
class ChainOfCustodyEntry:
    timestamp: str
    actor: str
    tool: str
    envelope_sha256: str


@dataclass
class EvidenceRecord:
    path: str
    host_path: str = ""
    sha256: str = ""
    md5: str = ""
    sha1: str = ""
    ssdeep: str = ""
    size_bytes: int = 0
    mime: str = ""
    acquired_by: str = ""
    evidence_type: str = ""
    chain_of_custody: list = field(default_factory=list)


@dataclass
class FindingRecord:
    identifier: str
    claim: str
    evidence_references: list
    tool_output_hash: str
    produced_by: str
    confidence: str = "weak"
    attack_techniques: list = field(default_factory=list)
    d3fend_defenses: list = field(default_factory=list)


@dataclass
class WorkerError:
    timestamp: str
    worker: str
    tool: str
    message: str


@dataclass
class CaseState:
    case_id: str
    evidence: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    candidate_files: list = field(default_factory=list)
    phase: str = "acquire"
    halted: bool = False
    halt_reason: str = ""
    summary: str = ""
    has_disk_image: bool = False
    has_memory_dump: bool = False
    has_pcap: bool = False
    has_windows_event_logs: bool = False
    has_portable_executable_candidates: bool = False
    has_encrypted_volume: bool = False


def create_initial_case_state(case_id, evidence_paths):
    evidence = [EvidenceRecord(path=path, host_path=path) for path in evidence_paths]
    return CaseState(case_id=case_id, evidence=evidence)


def find_evidence_by_path(case_state, path):
    for evidence_record in case_state.evidence:
        if evidence_record.path == path:
            return evidence_record
    return None


def find_finding_by_identifier(case_state, identifier):
    for finding_record in case_state.findings:
        if finding_record.identifier == identifier:
            return finding_record
    return None


def apply_evidence_hashes(case_state, path, sha256, md5, ssdeep, chain_entries):
    evidence_record = find_evidence_by_path(case_state, path)
    if evidence_record is None:
        return
    if sha256:
        evidence_record.sha256 = sha256
    if md5:
        evidence_record.md5 = md5
    if ssdeep:
        evidence_record.ssdeep = ssdeep
    for chain_entry in chain_entries:
        evidence_record.chain_of_custody.append(chain_entry)


def apply_evidence_classification(case_state, path, evidence_type, size_bytes, mime):
    evidence_record = find_evidence_by_path(case_state, path)
    if evidence_record is None:
        return
    evidence_record.acquired_by = "acquirer"
    if evidence_type:
        evidence_record.evidence_type = evidence_type
    if size_bytes:
        evidence_record.size_bytes = size_bytes
    if mime:
        evidence_record.mime = mime


def add_finding(case_state, finding_record):
    case_state.findings.append(finding_record)


def add_candidate_files(case_state, paths):
    for path in paths:
        if isinstance(path, str) and path not in case_state.candidate_files:
            case_state.candidate_files.append(path)


def add_attack_techniques(case_state, identifier, techniques):
    finding_record = find_finding_by_identifier(case_state, identifier)
    if finding_record is None:
        return
    for technique in techniques:
        if technique not in finding_record.attack_techniques:
            finding_record.attack_techniques.append(technique)


def add_defenses(case_state, identifier, defenses):
    finding_record = find_finding_by_identifier(case_state, identifier)
    if finding_record is None:
        return
    for defense in defenses:
        if defense not in finding_record.d3fend_defenses:
            finding_record.d3fend_defenses.append(defense)


def evidence_hash_set(case_state):
    return {
        evidence_record.sha256
        for evidence_record in case_state.evidence
        if evidence_record.sha256
    }


def hashed_evidence_paths(case_state):
    return [
        evidence_record.path
        for evidence_record in case_state.evidence
        if evidence_record.sha256
    ]
