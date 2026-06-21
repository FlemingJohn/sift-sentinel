"""
sift-tui — a live DFIR investigation dashboard for the SIFT Agent SDK pipeline.

This lives in its own folder but drives the controller defined in the sibling
`sift-agent/agent_sdk` project. It subscribes to a single event source:

  * the controller's AuditLogger, via a registered observer, which drives the
    AGENTS panel, the TOOL stream, the phase bar, and the status line;
  * the live CaseState handed back through on_case_state, which drives the
    FINDINGS and EVIDENCE panels.

Run it on the Windows host (in Windows Terminal), not inside WSL: the driver
launches the MCP servers into WSL itself via wsl.exe, and the host Python must
have both textual and claude_agent_sdk installed. Evidence paths stay in WSL form.
    python tui.py --case-id base-dc-01 --evidence /mnt/c/evidence/base-dc-cdrive.E01

If the agent code is not at the sibling ../sift-agent/agent_sdk, point to it with:
    SIFT_AGENT_DIR=/path/to/sift-agent/agent_sdk python tui.py ...
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

_AGENT_DIR = os.getenv("SIFT_AGENT_DIR") or str(
    Path(__file__).resolve().parent.parent / "sift-agent" / "agent_sdk"
)
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import DataTable, Footer, Header, RichLog, Static

from audit_logger import AuditLogger
from investigation_controller import run_investigation

PHASES = ["acquire", "hash", "analyze", "attribute", "report", "done"]
_STATUS_ICON = {"run": "⟳", "done": "✓", "error": "✗", "idle": "·"}
_CONF_DOT = {"confirmed": "●", "probable": "◐", "weak": "○"}


class LogMessage(Message):
    def __init__(self, kind: str, payload: dict) -> None:
        self.kind = kind
        self.payload = payload
        super().__init__()


class SiftTUI(App):
    CSS = """
    Screen { layout: vertical; }
    #phasebar { height: 1; padding: 0 1; background: $panel; }
    #body { height: 1fr; }
    #left  { width: 42%; border-right: solid $primary; }
    #right { width: 1fr; }
    .title { background: $primary; color: $text; text-style: bold; padding: 0 1; }
    #agents   { height: 45%; }
    #tools    { height: 1fr; }
    #findings { height: 55%; }
    #evidence { height: 1fr; }
    #summary { height: 32%; padding: 0 1; border-top: solid $primary; }
    #status { height: 1; dock: bottom; background: $panel; padding: 0 1; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("e", "export", "Export snapshot"),
        Binding("c", "clear_log", "Clear tool log"),
    ]

    def __init__(self, case_id: str, evidence: list[str]) -> None:
        super().__init__()
        self.case_id = case_id
        self.evidence = evidence
        self._audit: AuditLogger | None = None
        self._case_state = None
        self._agent_rows: set[str] = set()
        self._agent_status: dict[str, str] = {}
        self._finding_rows: set[str] = set()
        self._evidence_rows: set[str] = set()
        self._phase = ""

    # -- layout ---------------------------------------------------------- #
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(self._phase_bar(), id="phasebar")
        with Horizontal(id="body"):
            with Vertical(id="left"):
                yield Static("AGENTS", classes="title")
                yield DataTable(id="agents", cursor_type="row")
                yield Static("TOOL STREAM", classes="title")
                yield RichLog(id="tools", markup=True, wrap=False)
            with Vertical(id="right"):
                yield Static("FINDINGS", classes="title")
                yield DataTable(id="findings", cursor_type="row")
                yield Static("EVIDENCE & INTEGRITY", classes="title")
                yield DataTable(id="evidence", cursor_type="row")
        yield Static("REPORT SUMMARY", classes="title")
        yield RichLog(id="summary", markup=True, wrap=True)
        yield Static("", id="status")
        yield Footer()

    def on_mount(self) -> None:
        self.title = f"SIFT-Agent · case {self.case_id}"
        self.sub_title = "ANALYZING"

        self.query_one("#agents", DataTable).add_columns(
            "", "agent", "tools", "tok-in", "tok-out"
        )
        self.query_one("#findings", DataTable).add_columns(
            "id", "claim", "conf", "ATT&CK"
        )
        self.query_one("#evidence", DataTable).add_columns(
            "evidence", "sha256", "CoC"
        )

        self._update_status()
        self.run_worker(self._run_case(), exclusive=True, name="case")

    # -- the controller worker ------------------------------------------ #
    async def _run_case(self) -> None:
        audit = AuditLogger()
        audit.console_enabled = False
        audit.add_observer(self._on_event)
        self._audit = audit
        try:
            await run_investigation(
                self.case_id, self.evidence, audit, on_case_state=self._capture_state
            )
        except Exception as exc:  # surface, don't crash the UI
            self.post_message(
                LogMessage("error", {"source": "tui", "message": f"run failed: {exc}"})
            )
            self.sub_title = "ERROR"

    def _on_event(self, kind: str, payload: dict) -> None:
        # Called from the controller on the app's event loop; post_message is loop-safe.
        self.post_message(LogMessage(kind, payload))

    def _capture_state(self, case_state) -> None:
        self._case_state = case_state

    # -- events -> panels ----------------------------------------------- #
    def on_log_message(self, message: LogMessage) -> None:
        kind = message.kind
        payload = message.payload

        if kind == "phase_changed":
            self._phase = payload.get("phase", "")
            self.query_one("#phasebar", Static).update(self._phase_bar())
            self._write(f"[cyan][Phase][/] [b]{self._phase}[/]")
        elif kind == "specialist_started":
            name = payload.get("specialist", "?")
            self._agent_status[name] = "run"
            self._ensure_agent_row(name)
            self._write(f"[green][Agent][/] [b]{name}[/] - {payload.get('description', '')}")
        elif kind == "specialist_completed":
            name = payload.get("specialist", "?")
            self._agent_status[name] = "done"
            self._write(
                f"[green][Agent][/] [b]{name}[/] done  cost ${payload.get('cost_usd', 0):.4f}"
            )
        elif kind == "tool_invoked":
            name = payload.get("specialist", "?")
            self._ensure_agent_row(name)
            exit_code = payload.get("exit_code")
            failed = exit_code not in (None, 0)
            color = "red" if failed else "yellow"
            tail = ""
            if exit_code is not None:
                tail += f" exit={exit_code}"
            if payload.get("duration_ms") is not None:
                tail += f" {payload['duration_ms']}ms"
            self._write(f"[{color}][Tool][/] [dim]{name}[/] [b]{payload.get('tool', '?')}[/]{tail}")
        elif kind == "gate_evaluated":
            decision = payload.get("decision", "")
            color = "magenta" if decision == "ok" else "red"
            self._write(
                f"[magenta][Gate][/] [b]{payload.get('gate', '?')}[/] -> [{color}]{decision}[/]"
            )
        elif kind == "tool_denied":
            self._write(
                f"[red][Deny][/] [b]{payload.get('specialist', '?')}[/] "
                f"{payload.get('tool', '?')}: {payload.get('reason', '')}"
            )
        elif kind == "error":
            source = payload.get("source", "?")
            if source in self._agent_status:
                self._agent_status[source] = "error"
            self._write(f"[red][Error][/] [b]{source}[/] {payload.get('message', '')}")
        elif kind == "information":
            self._write(
                f"[blue][Info][/] [dim]{payload.get('source', '?')}[/] {payload.get('message', '')}"
            )
        elif kind == "case_completed":
            self._phase = "done"
            self.query_one("#phasebar", Static).update(self._phase_bar())
            self.sub_title = "COMPLETE"
            self._render_summary()

        self._render_agents()
        self._render_state()
        self._update_status()

    def _write(self, text: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.query_one("#tools", RichLog).write(f"[dim]{ts}[/] {text}")

    # -- AGENTS panel --------------------------------------------------- #
    def _ensure_agent_row(self, name: str) -> None:
        if name in self._agent_rows:
            return
        self.query_one("#agents", DataTable).add_row("·", name, "0", "0", "0", key=name)
        self._agent_rows.add(name)

    def _render_agents(self) -> None:
        audit = self._audit
        table = self.query_one("#agents", DataTable)
        cols = list(table.columns.keys())
        for name in self._agent_rows:
            status = self._agent_status.get(name, "idle")
            statistics = audit.statistics.get(name) if audit else None
            tools = statistics.tools_called if statistics else 0
            tokens_in = statistics.input_tokens if statistics else 0
            tokens_out = statistics.output_tokens if statistics else 0
            table.update_cell(name, cols[0], _STATUS_ICON.get(status, "·"))
            table.update_cell(name, cols[2], str(tools))
            table.update_cell(name, cols[3], str(tokens_in))
            table.update_cell(name, cols[4], str(tokens_out))

    # -- FINDINGS / EVIDENCE panels ------------------------------------- #
    def _render_state(self) -> None:
        if self._case_state is None:
            return
        self._render_findings(self._case_state.findings)
        self._render_evidence(self._case_state.evidence)

    def _render_summary(self) -> None:
        state = self._case_state
        box = self.query_one("#summary", RichLog)
        box.clear()
        if state is None:
            return
        if state.halted:
            box.write(f"[red]Investigation halted: {state.halt_reason}[/]")
            return
        if state.summary:
            box.write(state.summary)
            box.write("")
        for finding in state.findings:
            techniques = ", ".join(finding.attack_techniques) or "-"
            defenses = ", ".join(finding.d3fend_defenses) or "-"
            box.write(
                f"[b]{finding.identifier[:12]}[/]  "
                f"[yellow]ATT&CK[/] {techniques}   [magenta]D3FEND[/] {defenses}"
            )
            box.write(f"  {finding.claim}")

    def _render_findings(self, findings: list) -> None:
        table = self.query_one("#findings", DataTable)
        for finding in findings:
            key = finding.identifier
            confidence = finding.confidence
            row = [
                key[:12],
                (finding.claim or "")[:48],
                f"{_CONF_DOT.get(confidence, '○')} {confidence}",
                ",".join(finding.attack_techniques or []) or "-",
            ]
            if key in self._finding_rows:
                self._replace_row(table, key, row)
            else:
                table.add_row(*row, key=key)
                self._finding_rows.add(key)

    def _render_evidence(self, evidence: list) -> None:
        table = self.query_one("#evidence", DataTable)
        for record in evidence:
            key = record.host_path or record.path
            name = Path(record.path).name or record.path
            row = [
                name[:30],
                "✓" if record.sha256 else "…",
                "✓" if record.chain_of_custody else "…",
            ]
            if key in self._evidence_rows:
                self._replace_row(table, key, row)
            else:
                table.add_row(*row, key=key)
                self._evidence_rows.add(key)

    @staticmethod
    def _replace_row(table: DataTable, key: str, row: list) -> None:
        try:
            for col_key, value in zip(table.columns.keys(), row):
                table.update_cell(key, col_key, value)
        except Exception:
            pass

    # -- footer / phase bar / actions ----------------------------------- #
    def _update_status(self) -> None:
        audit = self._audit
        if audit is None:
            self.query_one("#status", Static).update(
                "[dim]starting...   q quit · e export · c clear[/]"
            )
            return
        tokens_in = sum(s.input_tokens for s in audit.statistics.values())
        tokens_out = sum(s.output_tokens for s in audit.statistics.values())
        tools = sum(s.tools_called for s in audit.statistics.values())
        errors = sum(s.errors for s in audit.statistics.values())
        self.query_one("#status", Static).update(
            f"[b]tokens[/] in {tokens_in:,} / out {tokens_out:,}   "
            f"[b]tools[/] {tools}   [b]errors[/] {errors}   "
            f"[b]est[/] ${audit.total_cost_usd():.4f}   "
            f"[dim]q quit · e export · c clear[/]"
        )

    def _phase_bar(self) -> str:
        return "  ▸  ".join(
            f"[reverse b] {phase} [/]" if phase == self._phase else f"[dim]{phase}[/]"
            for phase in PHASES
        )

    def action_clear_log(self) -> None:
        self.query_one("#tools", RichLog).clear()

    def action_export(self) -> None:
        out_dir = Path(os.getenv("SIFT_REPORTS_DIRECTORY", "./reports"))
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{self.case_id}.snapshot.json"
        snapshot = asdict(self._case_state) if self._case_state is not None else {}
        path.write_text(json.dumps(snapshot, indent=2, default=str), encoding="utf-8")
        self._write(f"[green][Export][/] wrote {path}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="sift-tui")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--evidence", required=True, nargs="+")
    args = parser.parse_args()
    SiftTUI(args.case_id, args.evidence).run()


if __name__ == "__main__":
    main()
