import hashlib
import json


def iter_json_values(text):
    decoder = json.JSONDecoder()
    index = 0
    length = len(text)
    while index < length:
        if text[index] in "{[":
            try:
                value, end = decoder.raw_decode(text, index)
            except json.JSONDecodeError:
                index += 1
                continue
            yield value
            index = end
        else:
            index += 1


def parse_first_json(text):
    if not text:
        return None
    for value in iter_json_values(text):
        return value
    return None


def parse_json_with_key(text, key):
    if not text:
        return None
    first_value = None
    for value in iter_json_values(text):
        if isinstance(value, dict) and key in value:
            return value
        if first_value is None:
            first_value = value
    return first_value


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
