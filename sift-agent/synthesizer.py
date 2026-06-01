from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal

from langchain_anthropic import ChatAnthropic
from pydantic import BaseModel, Field

from console_logger import log
from state import CaseState
from workers._base import sum_tokens


class ReportFinding(BaseModel):
    id: str
    claim: str
    evidence_refs: list[str]
    attack_techniques: list[str]
    d3fend_defenses: list[str] = Field(default_factory=list)
    confidence: Literal["confirmed", "probable", "weak"] = "weak"
    produced_by: str


class DroppedFinding(BaseModel):
    id: str
    reason: str


class ForensicReport(BaseModel):
    case_id: str
    summary: str
    findings: list[ReportFinding]
    dropped: list[DroppedFinding]
    evidence_count: int
    chain_of_custody_complete: bool


SYNTH_MODEL = os.getenv("SIFT_MODEL_SYNTH", "claude-opus-4-7")
REPORTS_DIR = Path(os.getenv("SIFT_REPORTS_DIR", "./reports"))


async def synthesizer_node(state: CaseState) -> dict:
    log.mark_opus("synthesizer")
    evidence = state.get("evidence") or []
    findings = state.get("findings") or []
    evidence_hashes = {e["sha256"] for e in evidence if e.get("sha256")}

    accepted: list[dict] = []
    dropped: list[DroppedFinding] = []
    for f in findings:
        refs = f.get("evidence_refs") or []
        att = f.get("attack_techniques") or []
        if not refs or not all(r in evidence_hashes for r in refs):
            dropped.append(DroppedFinding(
                id=f.get("id", "?"),
                reason="missing_or_unknown_evidence_ref",
            ))
            continue
        if not att:
            dropped.append(DroppedFinding(
                id=f.get("id", "?"),
                reason="missing_attack_mapping",
            ))
            continue
        accepted.append(f)

    log.agent_start(
        "synthesizer",
        f"validating {len(findings)} finding(s) -> "
        f"{len(accepted)} accepted / {len(dropped)} dropped",
    )

    model = ChatAnthropic(model=SYNTH_MODEL, temperature=0)
    brief = [
        {
            "claim": f["claim"],
            "techniques": f.get("attack_techniques", []),
            "defenses": f.get("d3fend_defenses", []),
            "confidence": f.get("confidence", "weak"),
        }
        for f in accepted
    ]
    prompt = (
        "You are the ReportSynthesizer for a forensic investigation. "
        "Using ONLY the validated findings below, write a five-sentence "
        "narrative summary describing what happened, the ATT&CK techniques "
        "observed, and recommended D3FEND defenses. Do NOT invent any "
        "indicator or technique not present in the findings."
    )
    task = (
        f"Case: {state.get('case_id')}\nValidated findings:\n"
        f"{json.dumps(brief, indent=2)}"
    )
    try:
        resp = await model.ainvoke(
            [
                {"role": "system", "content": prompt},
                {"role": "user", "content": task},
            ]
        )
        in_tok, out_tok = sum_tokens([resp])
        summary = resp.content if isinstance(resp.content, str) else json.dumps(resp.content)
    except Exception as e:
        log.error("synthesizer", f"narrative LLM failed: {e}")
        summary = (
            f"Forensic report for case {state.get('case_id')}: "
            f"{len(accepted)} validated findings."
        )
        in_tok = out_tok = 0

    coc_complete = all(
        (e.get("chain_of_custody") or []) for e in evidence
    )

    report = ForensicReport(
        case_id=state.get("case_id", "unknown"),
        summary=summary,
        findings=[
            ReportFinding(
                id=f["id"],
                claim=f["claim"],
                evidence_refs=f["evidence_refs"],
                attack_techniques=f.get("attack_techniques", []),
                d3fend_defenses=f.get("d3fend_defenses", []),
                confidence=f.get("confidence", "weak"),
                produced_by=f.get("produced_by", "unknown"),
            )
            for f in accepted
        ],
        dropped=dropped,
        evidence_count=len(evidence),
        chain_of_custody_complete=coc_complete,
    )

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = REPORTS_DIR / f"{report.case_id}.json"
    out_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")

    log.agent_done("synthesizer", in_tok, out_tok)
    log.info("synthesizer", f"report written -> {out_path}")
    return {"phase": "done"}
