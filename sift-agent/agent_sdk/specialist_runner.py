import json
from dataclasses import dataclass, field

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    HookMatcher,
    ResultMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
    query,
)

from audit_logger import estimate_cost_usd
from configuration import MAXIMUM_BUDGET_USD, MAXIMUM_TURNS_PER_SPECIALIST
from hooks import build_post_tool_use_audit, build_pre_tool_use_gate
from mcp_servers import (
    build_server_configurations,
    qualified_tool_names,
    servers_for_tools,
    unqualified_tool_name,
)
from text_parsing import extract_text_from_content


@dataclass
class SpecialistResult:
    final_text: str = ""
    tool_envelopes: list = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0


def tool_result_to_envelope(tool_result_block, pending_tool_names):
    text = extract_text_from_content(tool_result_block.content)
    try:
        envelope = json.loads(text)
    except json.JSONDecodeError:
        envelope = {}
    if not isinstance(envelope, dict):
        envelope = {"raw": text}
    tool_name = pending_tool_names.get(tool_result_block.tool_use_id, "unknown")
    envelope.setdefault("tool", tool_name)
    return envelope


def build_specialist_options(specialist_configuration, case_state, audit_logger):
    server_names = servers_for_tools(specialist_configuration.tool_names)
    pre_tool_use_gate = build_pre_tool_use_gate(
        case_state, audit_logger, specialist_configuration.name
    )
    post_tool_use_audit = build_post_tool_use_audit(
        case_state, audit_logger, specialist_configuration.name
    )
    return ClaudeAgentOptions(
        system_prompt=specialist_configuration.prompt,
        model=specialist_configuration.model_name,
        mcp_servers=build_server_configurations(server_names),
        allowed_tools=qualified_tool_names(specialist_configuration.tool_names),
        permission_mode="dontAsk",
        max_turns=MAXIMUM_TURNS_PER_SPECIALIST,
        max_budget_usd=MAXIMUM_BUDGET_USD,
        setting_sources=[],
        hooks={
            "PreToolUse": [HookMatcher(matcher="^mcp__", hooks=[pre_tool_use_gate])],
            "PostToolUse": [HookMatcher(matcher="^mcp__", hooks=[post_tool_use_audit])],
        },
    )


async def run_specialist(specialist_configuration, task_text, case_state, audit_logger):
    options = build_specialist_options(specialist_configuration, case_state, audit_logger)
    result = SpecialistResult()
    assistant_text_parts = []
    pending_tool_names = {}

    async for message in query(prompt=task_text, options=options):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, ToolUseBlock):
                    pending_tool_names[block.id] = unqualified_tool_name(block.name)
                elif isinstance(block, TextBlock):
                    assistant_text_parts.append(block.text)
        elif isinstance(message, UserMessage):
            blocks = message.content if isinstance(message.content, list) else []
            for block in blocks:
                if isinstance(block, ToolResultBlock):
                    envelope = tool_result_to_envelope(block, pending_tool_names)
                    result.tool_envelopes.append(envelope)
        elif isinstance(message, ResultMessage):
            usage = message.usage or {}
            result.input_tokens = int(usage.get("input_tokens") or 0)
            result.output_tokens = int(usage.get("output_tokens") or 0)
            if message.total_cost_usd is not None:
                result.cost_usd = message.total_cost_usd
            else:
                result.cost_usd = estimate_cost_usd(
                    result.input_tokens,
                    result.output_tokens,
                    specialist_configuration.is_supervisor,
                )
            if message.result:
                result.final_text = message.result

    if not result.final_text:
        result.final_text = " ".join(assistant_text_parts)
    return result
