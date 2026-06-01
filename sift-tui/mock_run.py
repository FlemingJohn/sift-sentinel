"""
mock_run.py — launch the real sift-tui dashboard with a SCRIPTED fake
investigation, so you can see the UI render on Windows with only Textual
installed (no WSL, no API key, no langgraph).

    python mock_run.py

It subclasses SiftTUI and overrides only the graph worker (_run_case),
emitting the same console_logger events + state snapshots the real graph
would produce.
"""
from __future__ import annotations

import asyncio

from tui import SiftTUI, log


def _sha(seed: str) -> str:
    import hashlib
    return hashlib.sha256(seed.encode()).hexdigest()


class MockSiftTUI(SiftTUI):
    async def _run_case(self) -> None:
        ev = self.evidence or [
            "/mnt/c/evidence/rocba-cdrive.e01",
            "/mnt/c/evidence/rocba-memory.raw",
        ]
        hashes = [_sha(p) for p in ev]
        log.mark_opus("attack_map")
        log.mark_opus("synthesizer")

        # ---- helpers ---------------------------------------------------
        evidence_raw = [{"path": p, "chain_of_custody": []} for p in ev]
        evidence_hashed = [
            {"path": p, "sha256": h, "chain_of_custody": [{"step": "hashed"}]}
            for p, h in zip(ev, hashes)
        ]
        findings: list[dict] = []

        def snap(phase: str, evid: list[dict]) -> None:
            self._apply_state({
                "phase": phase, "evidence": evid, "findings": list(findings),
            })

        # ---- acquire ---------------------------------------------------
        log.case_start(self.case_id)
        log.phase("acquire")
        snap("acquire", evidence_raw)
        log.agent_start("acquirer", f"identifying {len(ev)} evidence file(s)")
        await asyncio.sleep(0.5)
        log.tool("acquirer", "tool_ewfinfo", 0, 841)
        await asyncio.sleep(0.4)
        log.tool("acquirer", "tool_file", 0, 96)
        log.agent_done("acquirer", 1180, 220)

        # ---- hash ------------------------------------------------------
        log.phase("hash")
        log.agent_start("hasher", "computing sha256/md5/ssdeep")
        await asyncio.sleep(0.4)
        for p in ev:
            log.tool("hasher", "tool_sha256deep", 0, 1320)
        log.gate("hash_ok", "ok")
        log.agent_done("hasher", 640, 180)
        snap("verify", evidence_hashed)

        # ---- analyze (parallel specialists) ----------------------------
        log.phase("analyze")

        log.agent_start("filesystem", "walking NTFS, recovering deleted files")
        await asyncio.sleep(0.5)
        log.tool("filesystem", "tool_fls", 0, 2100)
        log.tool("filesystem", "tool_icat", 0, 410)
        findings.append({
            "id": "f3a1", "claim": "Run key persistence: HKCU\\...\\Run -> evil.exe",
            "evidence_refs": [hashes[0]], "confidence": "confirmed",
            "attack_techniques": [], "produced_by": "windows",
        })
        log.agent_done("filesystem", 5400, 720)
        snap("analyze", evidence_hashed)

        log.agent_start("windows", "parsing registry hives + event logs")
        await asyncio.sleep(0.5)
        log.tool("windows", "tool_evtxexport", 0, 1540)
        log.tool("windows", "tool_log2timeline_py", 0, 8800)
        findings.append({
            "id": "f7c2", "claim": "PowerShell download cradle in 4104 script block log",
            "evidence_refs": [hashes[0]], "confidence": "probable",
            "attack_techniques": [], "produced_by": "windows",
        })
        log.agent_done("windows", 9200, 1100)
        snap("analyze", evidence_hashed)

        if len(ev) > 1:
            log.agent_start("memory", "carving keys/strings from RAM")
            await asyncio.sleep(0.5)
            log.tool("memory", "tool_bulk_extractor", 0, 6100)
            findings.append({
                "id": "f9e0", "claim": "Suspicious outbound IP 185.x.x.x in memory strings",
                "evidence_refs": [hashes[1]], "confidence": "weak",
                "attack_techniques": [], "produced_by": "memory",
            })
            log.agent_done("memory", 3300, 540)
        snap("analyze", evidence_hashed)

        # ---- attribute (ATT&CK mapping, opus) --------------------------
        log.phase("attribute")
        log.agent_start("attack_map", f"mapping {len(findings)} finding(s) to ATT&CK")
        await asyncio.sleep(0.6)
        log.tool("attack_map", "map_finding_to_technique", 0, 220)
        tech = {"f3a1": ["T1547.001"], "f7c2": ["T1059.001"], "f9e0": ["T1071.001"]}
        for f in findings:
            f["attack_techniques"] = tech.get(f["id"], [])
        log.agent_done("attack_map", 4100, 880)
        snap("attribute", evidence_hashed)

        # ---- defend ----------------------------------------------------
        log.phase("defend")
        log.agent_start("defense_map", "mapping techniques to D3FEND")
        await asyncio.sleep(0.4)
        log.tool("defense_map", "list_defenses_for_attack", 0, 180)
        log.gate("attribution_ok", "ok")
        log.agent_done("defense_map", 900, 260)

        # ---- report (opus) ---------------------------------------------
        log.phase("done")
        log.agent_start("synthesizer", f"validating {len(findings)} finding(s)")
        await asyncio.sleep(0.6)
        log.agent_done("synthesizer", 6200, 1400)
        log.info("synthesizer", "report written -> reports/mock.json")
        snap("done", evidence_hashed)

        log.case_done(self.case_id)
        self.sub_title = "COMPLETE (mock)"
        self._final_state = {
            "phase": "done", "evidence": evidence_hashed, "findings": findings,
        }
        self._update_status()


def main() -> None:
    MockSiftTUI(
        case_id="mock-rocba",
        evidence=[
            "/mnt/c/evidence/rocba-cdrive.e01",
            "/mnt/c/evidence/rocba-memory.raw",
        ],
        backend="memory",
    ).run()


if __name__ == "__main__":
    main()
