import hashlib
import json
import re


JSON_OBJECT_OR_ARRAY = re.compile(r"(\{[\s\S]*\}|\[[\s\S]*\])")


def parse_first_json(text):
    if not text:
        return None
    match = JSON_OBJECT_OR_ARRAY.search(text)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None


def extract_text_from_content(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict):
                parts.append(part.get("text", ""))
            else:
                parts.append(getattr(part, "text", ""))
        return "".join(parts)
    return ""


def sha256_of_text(text):
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def envelope_hash(tool_envelope):
    serialized = json.dumps(tool_envelope, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
