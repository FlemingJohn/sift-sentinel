import json

from case_state import WorkerError
from forensic_records import current_timestamp
from gates import evidence_is_fully_hashed
from mcp_servers import unqualified_tool_name
from text_parsing import extract_text_from_content
from specialist_tools import (
    CARVER_TOOL_NAMES,
    CRYPTO_TOOL_NAMES,
    FILESYSTEM_TOOL_NAMES,
    MALWARE_STATIC_TOOL_NAMES,
    MEMORY_TOOL_NAMES,
    NETWORK_TOOL_NAMES,
    REVERSING_TOOL_NAMES,
    WINDOWS_TOOL_NAMES,
)


ANALYSIS_TOOL_NAMES = set(
    FILESYSTEM_TOOL_NAMES
    + CARVER_TOOL_NAMES
    + WINDOWS_TOOL_NAMES
    + MEMORY_TOOL_NAMES
    + NETWORK_TOOL_NAMES
    + MALWARE_STATIC_TOOL_NAMES
    + REVERSING_TOOL_NAMES
    + CRYPTO_TOOL_NAMES
)


def tool_envelope_from_response(tool_response):
    if isinstance(tool_response, dict) and "exit_code" in tool_response:
        return tool_response
    if isinstance(tool_response, dict):
        content = tool_response.get("content")
    else:
        content = tool_response
    text = extract_text_from_content(content)
    try:
        envelope = json.loads(text)
    except json.JSONDecodeError:
        envelope = {}
    if not isinstance(envelope, dict):
        envelope = {}
    return envelope


def build_pre_tool_use_gate(case_state, audit_logger, specialist_name):
    async def pre_tool_use_gate(input_data, tool_use_id, context):
        tool_name = unqualified_tool_name(input_data.get("tool_name", ""))
        if tool_name in ANALYSIS_TOOL_NAMES and not evidence_is_fully_hashed(case_state):
            reason = "Evidence is not fully hashed; analysis is blocked for chain of custody"
            audit_logger.tool_denied(specialist_name, tool_name, reason)
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }
        return {}

    return pre_tool_use_gate


def build_post_tool_use_audit(case_state, audit_logger, specialist_name):
    async def post_tool_use_audit(input_data, tool_use_id, context):
        tool_name = unqualified_tool_name(input_data.get("tool_name", ""))
        envelope = tool_envelope_from_response(input_data.get("tool_response", {}))
        exit_code = envelope.get("exit_code")
        duration_ms = envelope.get("duration_ms")
        audit_logger.tool_invoked(specialist_name, tool_name, exit_code, duration_ms)
        if exit_code is not None and exit_code != 0:
            case_state.errors.append(WorkerError(
                timestamp=current_timestamp(),
                worker=specialist_name,
                tool=tool_name,
                message=envelope.get("stderr", "") or "non-zero exit code",
            ))
        return {}

    return post_tool_use_audit
