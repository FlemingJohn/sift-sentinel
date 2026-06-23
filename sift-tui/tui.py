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
from collections import Counter
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

_AGENT_DIR = os.getenv("SIFT_AGENT_DIR") or str(
    Path(__file__).resolve().parent.parent / "sift-agent" / "agent_sdk"
)
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import DataTable, Footer, Header, RichLog, Static

from audit_logger import AuditLogger
from configuration import MAXIMUM_BUDGET_USD
from investigation_controller import run_investigation

PHASES = ["acquire", "hash", "analyze", "attribute", "report", "done"]
_STATUS_ICON = {"run": "⟳", "done": "✓", "error": "✗", "idle": "·"}
_CONF_DOT = {"confirmed": "●", "probable": "◐", "weak": "○"}
_CONF_RANK = {"confirmed": 0, "probable": 1, "weak": 2}
_CONF_STYLE = {"confirmed": "bold green", "probable": "yellow", "weak": "dim"}


class LogMessage(Message):
    def __init__(self, kind: str, payload: dict) -> None:
        self.kind = kind
        self.payload = payload
        super().__init__()


class SiftTUI(App):
    CSS = """
    Screen { layout: vertical; }
    #phasebar { height: 1; padding: 0 1; background: $panel; }
    #phasebar.-flash-bad { background: $error; color: $text; }
    #phasebar.-flash-ok { background: $success; color: $text; }
    #alert { height: 1; padding: 0 1; }
    #alert.-active { background: $error; color: $text; text-style: bold; }
    #alert.-warn { background: $warning; color: $text; text-style: bold; }
    #body { height: 1fr; }
    #left  { width: 42%; border-right: solid $primary; }
    #right { width: 1fr; }
    .title { background: $primary; color: $text; text-style: bold; padding: 0 1; }
    #agents   { height: 35%; }
    #tools    { height: 1fr; }
    #critical { height: 9; border-top: solid $error; }
    #findings { height: 55%; }
    #evidence { height: 1fr; }
    #summary { height: 32%; padding: 0 1; border-top: solid $primary; }
    #status { height: 1; dock: bottom; background: $panel; padding: 0 1; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("e", "export", "Export snapshot"),
        Binding("c", "clear_log", "Clear tool log"),
        Binding("a", "ack", "Ack alert"),
    ]

    def __init__(self, case_id: str, evidence: list[str]) -> None:
        super().__init__()
        self.case_id = case_id
        self.evidence = evidence
        self._audit: AuditLogger | None = None
        self._case_state = None
        self._agent_rows: set[str] = set()
        self._agent_status: dict[str, str] = {}
        self._evidence_rows: set[str] = set()
        self._phase = ""
        # terminal-state + alert tracking
        self._halted = False
        self._completed = False
        self._halt_phase = ""
        self._alert_text = ""
        self._alert_level = "error"
        self._alert_count = 0

    # -- layout ---------------------------------------------------------- #
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(self._phase_bar(), id="phasebar")
        yield Static("[dim]● no alerts[/]", id="alert")
        with Horizontal(id="body"):
            with Vertical(id="left"):
                yield Static("AGENTS", classes="title")
                yield DataTable(id="agents", cursor_type="row")
                yield Static("TOOL STREAM", classes="title")
                yield RichLog(id="tools", markup=True, wrap=False)
                yield Static("CRITICAL", classes="title", id="critical-title")
                yield RichLog(id="critical", markup=True, wrap=True)
            with Vertical(id="right"):
                yield Static("FINDINGS", classes="title", id="findings-title")
                yield DataTable(id="findings", cursor_type="row")
                yield Static("EVIDENCE & INTEGRITY", classes="title")
                yield DataTable(id="evidence", cursor_type="row")
        yield Static("REPORT SUMMARY", classes="title", id="summary-title")
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
            gate = payload.get("gate", "?")
            decision = payload.get("decision", "")
            color = "magenta" if decision == "ok" else "red"
            self._write(f"[magenta][Gate][/] [b]{gate}[/] -> [{color}]{decision}[/]")
            if decision != "ok":
                self._raise_alert(f"GATE FAILED: {gate}", "error")
                self._write_critical(f"[b red]GATE FAILED[/] {gate}")
                self.query_one("#phasebar", Static).update(self._phase_bar())
        elif kind == "tool_denied":
            specialist = payload.get("specialist", "?")
            tool = payload.get("tool", "?")
            reason = payload.get("reason", "")
            self._write(f"[red][Deny][/] [b]{specialist}[/] {tool}: {reason}")
            self._raise_alert(f"DENIED: {specialist}/{tool} — {reason}", "warn")
            self._write_critical(f"[b yellow]DENY[/] {specialist}/{tool}: {reason}")
        elif kind == "error":
            source = payload.get("source", "?")
            message = payload.get("message", "")
            if source in self._agent_status:
                self._agent_status[source] = "error"
            self._write(f"[red][Error][/] [b]{source}[/] {message}")
            self._write_critical(f"[b red]ERROR[/] {source}: {message}")
            # "halt" is the controller's halt signal; the headline is set on
            # case_completed, so only non-halt errors raise the banner here.
            if source != "halt":
                self._raise_alert(f"ERROR: {source} — {message}", "error")
        elif kind == "information":
            self._write(
                f"[blue][Info][/] [dim]{payload.get('source', '?')}[/] {payload.get('message', '')}"
            )
        elif kind == "case_completed":
            self._finish_case()

        self._render_agents()
        self._render_state()
        self._update_status()

    def _write(self, text: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.query_one("#tools", RichLog).write(f"[dim]{ts}[/] {text}")

    # -- alerts / critical pane / attention ----------------------------- #
    def _write_critical(self, text: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.query_one("#critical", RichLog).write(f"[dim]{ts}[/] {text}")

    def _raise_alert(self, message: str, level: str = "error") -> None:
        # A halt (error) outranks a denial (warn): never let a warn overwrite it.
        if self._alert_level == "error" and level == "warn" and self._alert_text:
            self._alert_count += 1
            self._refresh_alert()
            return
        self._alert_count += 1
        self._alert_text = message
        self._alert_level = level
        self._refresh_alert()

    def _refresh_alert(self) -> None:
        bar = self.query_one("#alert", Static)
        bar.remove_class("-active")
        bar.remove_class("-warn")
        if not self._alert_text:
            bar.update("[dim]● no alerts[/]")
            return
        bar.add_class("-warn" if self._alert_level == "warn" else "-active")
        label = "WARN" if self._alert_level == "warn" else "ALERT"
        suffix = f"   ({self._alert_count} total · a to ack)"
        bar.update(f"[b]{label}[/]  {self._alert_text}{suffix}")

    def _attention(self, level: str) -> None:
        try:
            self.bell()
        except Exception:
            pass
        bar = self.query_one("#phasebar", Static)
        css_class = "-flash-ok" if level == "done" else "-flash-bad"
        ticks = {"count": 0}

        def pulse() -> None:
            bar.toggle_class(css_class)
            ticks["count"] += 1
            if ticks["count"] >= 6:
                bar.remove_class(css_class)
                timer.stop()

        timer = self.set_interval(0.3, pulse)

    def _finish_case(self) -> None:
        state = self._case_state
        if state is not None and state.halted:
            self._halted = True
            self._halt_phase = self._phase
            self.sub_title = "HALTED"
            self._raise_alert(f"HALTED: {state.halt_reason}", "error")
            self.query_one("#summary-title", Static).update(
                "[b white on red] INVESTIGATION HALTED [/]"
            )
            self._attention("halted")
        else:
            self._completed = True
            self._phase = "done"
            self.sub_title = "COMPLETE"
            self.query_one("#summary-title", Static).update(
                "[b black on green] REPORT READY [/]"
            )
            self._attention("done")
        self.query_one("#phasebar", Static).update(self._phase_bar())
        self._render_summary()

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
        # Rebuild so confirmed findings always sort above weaker ones and never
        # hide below noise; the finding set is small, so the churn is cheap.
        table.clear()
        ordered = sorted(findings, key=lambda f: _CONF_RANK.get(f.confidence, 3))
        for finding in ordered:
            confidence = finding.confidence
            conf_cell = Text(
                f"{_CONF_DOT.get(confidence, '○')} {confidence}",
                style=_CONF_STYLE.get(confidence, ""),
            )
            table.add_row(
                finding.identifier[:12],
                (finding.claim or "")[:48],
                conf_cell,
                ",".join(finding.attack_techniques or []) or "-",
                key=finding.identifier,
            )
        counts = Counter(f.confidence for f in findings)
        self.query_one("#findings-title", Static).update(
            f"FINDINGS — [green]{counts.get('confirmed', 0)}●[/] "
            f"[yellow]{counts.get('probable', 0)}◐[/] "
            f"[dim]{counts.get('weak', 0)}○[/]"
        )

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
        errors_text = f"[b red]{errors}[/]" if errors else "0"
        self.query_one("#status", Static).update(
            f"[b]tokens[/] in {tokens_in:,} / out {tokens_out:,}   "
            f"[b]tools[/] {tools}   [b]errors[/] {errors_text}   "
            f"[b]est[/] {self._cost_text(audit.total_cost_usd())}   "
            f"[dim]q quit · e export · c clear · a ack[/]"
        )

    @staticmethod
    def _cost_text(cost: float) -> str:
        budget = MAXIMUM_BUDGET_USD
        if budget and cost >= budget:
            return f"[b red]${cost:.4f} / ${budget:.2f} OVER[/]"
        if budget and cost >= 0.8 * budget:
            return f"[b yellow]${cost:.4f} / ${budget:.2f}[/]"
        if budget:
            return f"${cost:.4f} / ${budget:.2f}"
        return f"${cost:.4f}"

    def _phase_bar(self) -> str:
        try:
            active_index = PHASES.index(self._phase)
        except ValueError:
            active_index = len(PHASES)
        parts = []
        for index, phase in enumerate(PHASES):
            if self._halted and phase == self._halt_phase:
                parts.append(f"[b white on red] ✗ {phase} [/]")
            elif self._completed and phase == "done":
                parts.append(f"[b black on green] ✓ {phase} [/]")
            elif index < active_index:
                parts.append(f"[green]✓ {phase}[/]")
            elif index == active_index and not self._halted and not self._completed:
                parts.append(f"[reverse b] ⟳ {phase} [/]")
            else:
                parts.append(f"[dim]{phase}[/]")
        return "  ▸  ".join(parts)

    def action_clear_log(self) -> None:
        self.query_one("#tools", RichLog).clear()

    def action_ack(self) -> None:
        self._alert_text = ""
        self._alert_count = 0
        self._alert_level = "error"
        self._refresh_alert()

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
