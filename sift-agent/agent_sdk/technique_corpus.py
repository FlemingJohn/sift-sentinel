import json
import os
from pathlib import Path


DEFAULT_CORPUS_DIRECTORY = (
    Path(__file__).resolve().parent.parent.parent
    / "sift-mcp-servers"
    / "mitre-attack"
)

CORPUS_DIRECTORY = Path(os.getenv("SIFT_TECHNIQUE_CORPUS_DIR", DEFAULT_CORPUS_DIRECTORY))

DOMAIN_BUNDLES = (
    CORPUS_DIRECTORY / "enterprise-attack.json",
    CORPUS_DIRECTORY / "ics-attack.json",
    CORPUS_DIRECTORY / "mobile-attack.json",
)


def mitre_external_id(stix_object):
    for reference in stix_object.get("external_references", []) or []:
        if reference.get("source_name") == "mitre-attack":
            return reference.get("external_id")
    return None


def load_valid_technique_ids():
    valid_identifiers = set()
    for bundle_path in DOMAIN_BUNDLES:
        if not bundle_path.is_file():
            continue
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        for stix_object in bundle.get("objects", []):
            if stix_object.get("type") != "attack-pattern":
                continue
            external_id = mitre_external_id(stix_object)
            if external_id:
                valid_identifiers.add(external_id.upper())
    return valid_identifiers


def filter_valid_techniques(technique_ids, valid_identifiers):
    accepted = []
    rejected = []
    for technique_id in technique_ids:
        if not technique_id:
            continue
        normalized = technique_id.strip().upper()
        if normalized in valid_identifiers:
            if normalized not in accepted:
                accepted.append(normalized)
        elif technique_id not in rejected:
            rejected.append(technique_id)
    return accepted, rejected
