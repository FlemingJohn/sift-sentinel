from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timezone

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import AIMessage, ToolMessage
from langgraph.prebuilt import create_react_agent

from console_logger import log

HAIKU = os.getenv("SIFT_MODEL_WORKER",     "claude-haiku-4-5-20251001")
OPUS  = os.getenv("SIFT_MODEL_SUPERVISOR", "claude-opus-4-7")


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id() -> str:
    return uuid.uuid4().hex[:12]


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()


def envelope_hash(env: dict) -> str:
    return hashlib.sha256(
        json.dumps(env, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def parse_first_json(text: str) -> dict | list | None:
    if not text:
        return None
    m = re.search(r"(\{[\s\S]*\}|\[[\s\S]*\])", text)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None


def collect_tool_envelopes(messages: list) -> list[dict]:
    out: list[dict] = []
    for m in messages:
        if isinstance(m, ToolMessage):
            content = m.content if isinstance(m.content, str) else json.dumps(m.content)
            try:
                env = json.loads(content)
            except Exception:
                env = {"raw": content, "tool": getattr(m, "name", None)}
            if not isinstance(env, dict):
                env = {"raw": env, "tool": getattr(m, "name", None)}
            env.setdefault("tool", getattr(m, "name", None))
            out.append(env)
    return out


def sum_tokens(messages: list) -> tuple[int, int]:
    in_tok = out_tok = 0
    for m in messages:
        usage = getattr(m, "usage_metadata", None)
        if isinstance(usage, dict):
            in_tok  += int(usage.get("input_tokens")  or 0)
            out_tok += int(usage.get("output_tokens") or 0)
    return in_tok, out_tok


def final_text(result: dict) -> str:
    msgs = result.get("messages", [])
    for m in reversed(msgs):
        if isinstance(m, AIMessage):
            content = m.content
            if isinstance(content, list):
                return " ".join(
                    p.get("text", "") for p in content if isinstance(p, dict)
                )
            return content or ""
    return ""


def append_chain(ev: dict, *, actor: str, tool: str, envelope_sha: str) -> dict:
    chain = list(ev.get("chain_of_custody") or [])
    chain.append({
        "ts": now(),
        "actor": actor,
        "tool": tool,
        "envelope_sha256": envelope_sha,
    })
    return {**ev, "chain_of_custody": chain}


def make_finding(
    *,
    produced_by: str,
    claim: str,
    evidence_refs: list[str],
    messages: list,
    confidence: str = "weak",
) -> dict:
    return {
        "id": new_id(),
        "claim": claim,
        "evidence_refs": list(evidence_refs or []),
        "tool_output_hash": sha256_text(
            json.dumps(collect_tool_envelopes(messages), default=str)
        ),
        "confidence": confidence,
        "attack_techniques": [],
        "d3fend_defenses": [],
        "produced_by": produced_by,
    }


async def run_react(
    *,
    name: str,
    tools: list,
    prompt: str,
    task: str,
    doing: str | None = None,
    model_id: str | None = None,
    recursion_limit: int = 25,
) -> dict:
    log.agent_start(name, doing or task[:80])
    model = ChatAnthropic(model=model_id or HAIKU, temperature=0)
    agent = create_react_agent(model, tools, prompt=prompt, name=name)
    try:
        result = await agent.ainvoke(
            {"messages": [{"role": "user", "content": task}]},
            config={"recursion_limit": recursion_limit},
        )
    except Exception as e:
        log.error(name, f"agent crashed: {e}")
        return {"messages": []}

    msgs = result.get("messages", [])
    for env in collect_tool_envelopes(msgs):
        log.tool(
            agent=name,
            tool=env.get("tool") or "unknown",
            exit_code=env.get("exit_code"),
            duration_ms=env.get("duration_ms"),
        )
    in_tok, out_tok = sum_tokens(msgs)
    log.agent_done(name, in_tok, out_tok)
    return result
