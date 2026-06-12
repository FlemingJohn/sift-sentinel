import json
import uuid
from datetime import datetime, timezone

from case_state import ChainOfCustodyEntry, FindingRecord
from text_parsing import envelope_hash, sha256_of_text


def current_timestamp():
    return datetime.now(timezone.utc).isoformat()


def new_identifier():
    return uuid.uuid4().hex[:12]


def build_finding(produced_by, claim, evidence_references, tool_envelopes, confidence):
    serialized_envelopes = json.dumps(tool_envelopes, default=str)
    return FindingRecord(
        identifier=new_identifier(),
        claim=claim,
        evidence_references=list(evidence_references),
        tool_output_hash=sha256_of_text(serialized_envelopes),
        produced_by=produced_by,
        confidence=confidence,
        attack_techniques=[],
        d3fend_defenses=[],
    )


def build_chain_entries(actor, tool_envelopes):
    chain_entries = []
    for tool_envelope in tool_envelopes:
        tool_name = tool_envelope.get("tool") or "unknown"
        chain_entries.append(ChainOfCustodyEntry(
            timestamp=current_timestamp(),
            actor=actor,
            tool=tool_name,
            envelope_sha256=envelope_hash(tool_envelope),
        ))
    return chain_entries
