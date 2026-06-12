def evidence_is_fully_hashed(case_state):
    if not case_state.evidence:
        return False
    return all(evidence_record.sha256 for evidence_record in case_state.evidence)


def findings_have_attribution(case_state):
    if not case_state.findings:
        return False
    return all(finding_record.attack_techniques for finding_record in case_state.findings)


def determine_halt_reason(case_state):
    if case_state.halt_reason:
        return case_state.halt_reason
    if not case_state.evidence:
        return "no_evidence"
    if not all(evidence_record.sha256 for evidence_record in case_state.evidence):
        return "unhashed_evidence"
    if not all(finding_record.attack_techniques for finding_record in case_state.findings):
        return "missing_attack_attribution"
    return "unknown"
