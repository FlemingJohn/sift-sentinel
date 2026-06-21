from dataclasses import dataclass

from configuration import SUPERVISOR_MODEL_NAME, WORKER_MODEL_NAME
from specialist_tools import SPECIALIST_TOOL_ALLOWLISTS


@dataclass
class SpecialistConfiguration:
    name: str
    description: str
    prompt: str
    model_name: str
    tool_names: list
    is_supervisor: bool = False


ACQUIRER_PROMPT = (
    "You are the image acquirer. For each evidence path, determine its type "
    "(disk image such as E01, AFF, raw, img, dd; memory dump such as mem, vmem, dmp; "
    "packet capture such as pcap, pcapng; or other) and its size in bytes. "
    "Use ewfinfo for E01, affinfo for AFF, disktype for raw images, and "
    "tsk_imageinfo when useful. Do not mount anything destructive. "
    "Reply only with a JSON object of the form "
    '{"images": [{"path": "...", "type": "disk|memory|pcap|other", '
    '"size_bytes": 0, "mime": "..."}]}.'
)

HASHER_PROMPT = (
    "You are the integrity hasher. For every evidence file path, compute the "
    "sha256, md5, and ssdeep fuzzy hash using the hashing tools sha256deep, "
    "md5deep, and ssdeep. Use one tool call per hash family. "
    "Reply only with a JSON object of the form "
    '{"hashes": [{"path": "...", "sha256": "...", "md5": "...", "ssdeep": "..."}]}.'
)

FILESYSTEM_PROMPT = (
    "You are the filesystem analyst. Given disk images, enumerate partitions with "
    "mmls, inspect filesystems with fsstat, list directories with fls, extract "
    "suspicious files with icat, and gather MFT and inode metadata with istat. "
    "Look for unsigned executables in unusual paths, recently modified system "
    "binaries, suspicious scheduled task definitions, alternate data streams, and "
    "deleted but recoverable suspicious files. "
    "Reply only with a JSON object of the form "
    '{"findings": [{"claim": "short statement", "candidate_files": ["/path/in/image"]}]}.'
)

CARVER_PROMPT = (
    "You are the file carver. Recover deleted and unallocated content from disk "
    "images using foremost, scalpel, and photorec, then identify recovered file "
    "types with fidentify and exif. Report recovered artifacts that have forensic "
    "value. "
    "Reply only with a JSON object of the form "
    '{"findings": [{"claim": "short statement", "candidate_files": ["/path/in/image"]}]}.'
)

WINDOWS_PROMPT = (
    "You are the Windows artifact analyst. Parse Windows event logs with evtxexport, "
    "registry hives with regfexport, and ESE databases with esedbexport. Extract "
    "credential material indicators with samdump2 and examine shadow copies with "
    "vshadowinfo. Look for persistence, lateral movement, and credential access. "
    "Reply only with a JSON object of the form "
    '{"findings": [{"claim": "short statement", "candidate_files": ["/path/in/image"]}]}.'
)

MEMORY_PROMPT = (
    "You are the memory analyst. Examine memory dumps for cryptographic key material "
    "with aeskeyfind and rsakeyfind, measure entropy with ent, and extract artifacts "
    "with bulk_extractor. Report indicators of injected code, hidden processes, and "
    "recovered secrets. "
    "Reply only with a JSON object of the form "
    '{"findings": [{"claim": "short statement", "candidate_files": ["/path/in/image"]}]}.'
)

NETWORK_PROMPT = (
    "You are the network analyst. Reconstruct flows from packet captures with tcpflow "
    "and tcptrace, profile traffic with nfdump, and search payloads with ngrep. "
    "Identify command and control, exfiltration, and suspicious protocols. "
    "Reply only with a JSON object of the form "
    '{"findings": [{"claim": "short statement", "candidate_files": ["/path/in/capture"]}]}.'
)

MALWARE_STATIC_PROMPT = (
    "You are the static malware analyst. Examine candidate executables statically "
    "with readpe, pescan, pesec, and pestr, compute import hashes with pehash, and "
    "scan with clamscan. Never execute any sample. Report packers, suspicious imports, "
    "and signature matches. "
    "Reply only with a JSON object of the form "
    '{"findings": [{"claim": "short statement", "candidate_files": ["/path/to/sample"]}]}.'
)

REVERSING_PROMPT = (
    "You are the reverse engineer. Disassemble and inspect candidate binaries "
    "statically with radare2, rabin2, and rahash2. Never run any sample. Report "
    "capabilities, embedded strings, and notable functions. "
    "Reply only with a JSON object of the form "
    '{"findings": [{"claim": "short statement", "candidate_files": ["/path/to/sample"]}]}.'
)

CRYPTO_PROMPT = (
    "You are the cryptographic volume analyst. Inspect encrypted volumes with "
    "dislocker for BitLocker and fvdeinfo for FileVault, and assess passwords with "
    "ccguess. Report encryption schemes detected and recovery feasibility. "
    "Reply only with a JSON object of the form "
    '{"findings": [{"claim": "short statement", "candidate_files": ["/path/to/volume"]}]}.'
)

ATTACK_MAP_PROMPT = (
    "You are the attack mapper. For each finding, call map_finding_to_technique on "
    "the claim and choose technique identifiers ONLY from the matches it returns. "
    "Do not invent identifiers or recall them from memory; confirm each chosen "
    "identifier with get_technique_details. Prefer specific sub-techniques. If no "
    "returned match genuinely fits a finding, omit that finding rather than "
    "guessing. "
    "Reply only with a JSON object of the form "
    '{"patches": [{"id": "finding-id", "attack_techniques": ["T1059.001"]}]}.'
)

DEFENSE_MAP_PROMPT = (
    "You are the defense mapper. For each finding's attack techniques, look up the "
    "D3FEND defenses that map to them with list_defenses_for_attack, then verify each "
    "with get_defense. "
    "Reply only with a JSON object of the form "
    '{"patches": [{"id": "finding-id", "d3fend_defenses": ["D3-AMED"]}]}.'
)


SPECIALIST_DEFINITIONS = {
    "acquirer": SpecialistConfiguration(
        name="acquirer",
        description="Identifies and characterises evidence files",
        prompt=ACQUIRER_PROMPT,
        model_name=WORKER_MODEL_NAME,
        tool_names=SPECIALIST_TOOL_ALLOWLISTS["acquirer"],
    ),
    "hasher": SpecialistConfiguration(
        name="hasher",
        description="Computes integrity hashes for chain of custody",
        prompt=HASHER_PROMPT,
        model_name=WORKER_MODEL_NAME,
        tool_names=SPECIALIST_TOOL_ALLOWLISTS["hasher"],
    ),
    "filesystem": SpecialistConfiguration(
        name="filesystem",
        description="Walks filesystems and extracts suspicious files",
        prompt=FILESYSTEM_PROMPT,
        model_name=WORKER_MODEL_NAME,
        tool_names=SPECIALIST_TOOL_ALLOWLISTS["filesystem"],
    ),
    "carver": SpecialistConfiguration(
        name="carver",
        description="Recovers deleted and unallocated content",
        prompt=CARVER_PROMPT,
        model_name=WORKER_MODEL_NAME,
        tool_names=SPECIALIST_TOOL_ALLOWLISTS["carver"],
    ),
    "windows": SpecialistConfiguration(
        name="windows",
        description="Parses Windows event logs and registry artifacts",
        prompt=WINDOWS_PROMPT,
        model_name=WORKER_MODEL_NAME,
        tool_names=SPECIALIST_TOOL_ALLOWLISTS["windows"],
    ),
    "memory": SpecialistConfiguration(
        name="memory",
        description="Analyses memory dumps for secrets and artifacts",
        prompt=MEMORY_PROMPT,
        model_name=WORKER_MODEL_NAME,
        tool_names=SPECIALIST_TOOL_ALLOWLISTS["memory"],
    ),
    "network": SpecialistConfiguration(
        name="network",
        description="Reconstructs and inspects network captures",
        prompt=NETWORK_PROMPT,
        model_name=WORKER_MODEL_NAME,
        tool_names=SPECIALIST_TOOL_ALLOWLISTS["network"],
    ),
    "malware_static": SpecialistConfiguration(
        name="malware_static",
        description="Performs static analysis of candidate executables",
        prompt=MALWARE_STATIC_PROMPT,
        model_name=WORKER_MODEL_NAME,
        tool_names=SPECIALIST_TOOL_ALLOWLISTS["malware_static"],
    ),
    "reversing": SpecialistConfiguration(
        name="reversing",
        description="Disassembles candidate binaries statically",
        prompt=REVERSING_PROMPT,
        model_name=WORKER_MODEL_NAME,
        tool_names=SPECIALIST_TOOL_ALLOWLISTS["reversing"],
    ),
    "crypto": SpecialistConfiguration(
        name="crypto",
        description="Inspects encrypted volumes",
        prompt=CRYPTO_PROMPT,
        model_name=WORKER_MODEL_NAME,
        tool_names=SPECIALIST_TOOL_ALLOWLISTS["crypto"],
    ),
    "attack_map": SpecialistConfiguration(
        name="attack_map",
        description="Maps findings to MITRE ATT&CK techniques",
        prompt=ATTACK_MAP_PROMPT,
        model_name=WORKER_MODEL_NAME,
        tool_names=SPECIALIST_TOOL_ALLOWLISTS["attack_map"],
    ),
    "defense_map": SpecialistConfiguration(
        name="defense_map",
        description="Maps findings to D3FEND defenses",
        prompt=DEFENSE_MAP_PROMPT,
        model_name=WORKER_MODEL_NAME,
        tool_names=SPECIALIST_TOOL_ALLOWLISTS["defense_map"],
    ),
}
