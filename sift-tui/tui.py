"""
sift-tui — a live DFIR investigation dashboard for the SIFT agent pipeline.

This lives in its own folder but drives the graph defined in the sibling
`sift-agent` project. It consumes two event sources:

  * the graph's `astream(stream_mode="values")` -> full case-state snapshots,
    which drive the FINDINGS and EVIDENCE panels;
  * the shared `console_logger` event stream (via a registered TuiSink) ->
    fine-grained AGENT and TOOL activity.

Run it inside WSL/Linux so the MCP servers can reach the SIFT binaries:
    python tui.py --case-id rocba-01 --evidence /mnt/c/evidence/rocba-cdrive.e01

If sift-agent is not the sibling folder ../sift-agent, point to it with:
    SIFT_AGENT_DIR=/path/to/sift-agent python tui.py ...
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# --------------------------------------------------------------------------- #
#  Bootstrap: make the sibling sift-agent package importable
# --------------------------------------------------------------------------- #
_AGENT_DIR = os.getenv("SIFT_AGENT_DIR") or str(
    Path(__file__).resolve().parent.parent / "sift-agent"
)
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

from dotenv import load_dotenv

load_dotenv(Path(_AGENT_DIR) / ".env")

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import DataTable, Footer, Header, RichLog, Static
from textual.worker import get_current_worker

from typing import TYPE_CHECKING                # noqa: E402

from console_logger import Event, log          # noqa: E402  (after path bootstrap)

if TYPE_CHECKING:                               # heavy imports stay lazy so the
    from state import CaseState                 # TUI can launch with only Textual

PHASES = ["acquire", "hash", "analyze", "attribute", "defend", "done"]
_STATUS_ICON = {"run": "⟳", "done": "✓", "error": "✗", "idle": "·"}
_CONF_DOT = {"confirmed": "●", "probable": "◐", "weak": "○"}


# --------------------------------------------------------------------------- #
#  Bridge: console_logger Event -> Textual Message
# --------------------------------------------------------------------------- #
class LogMessage(Message):
    def __init__(self, event: Event) -> None:
        self.event = event
        super().__init__()


class TuiSink:
    """A console_logger sink that forwards every event into the Textual app."""

    def __init__(self, app: "SiftTUI") -> None:
        self._app = app

    def handle(self, ev: Event) -> None:
        # post_message is loop-safe; the app processes it on its own loop.
        self._app.post_message(LogMessage(ev))


# --------------------------------------------------------------------------- #
#  The app
# --------------------------------------------------------------------------- #
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
    #status { height: 1; dock: bottom; background: $panel; padding: 0 1; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("e", "export", "Export snapshot"),
        Binding("c", "clear_log", "Clear tool log"),
    ]

    def __init__(self, case_id: str, evidence: list[str], backend: str) -> None:
        super().__init__()
        self.case_id = case_id
        self.evidence = evidence
        self.backend = backend
        self._agent_rows: set[str] = set()
        self._finding_rows: set[str] = set()
        self._evidence_rows: set[str] = set()
        self._final_state: dict | None = None
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

        # Route logger events into the TUI; silence the console renderer.
        self._sink = TuiSink(self)
        log.add_sink(self._sink)
        log.use_console(False)
        self._update_status()

        self.run_worker(self._run_case(), exclusive=True, name="case")

    # -- the graph worker ------------------------------------------------ #
    async def _run_case(self) -> None:
        from graph import build_graph           # lazy: needs langgraph + WSL

        initial: "CaseState" = {
            "case_id": self.case_id,
            "evidence": [
                {"path": p, "chain_of_custody": []} for p in self.evidence
            ],
            "findings": [],
            "errors": [],
            "candidate_files": [],
        }
        config = {
            "configurable": {"thread_id": f"case-{self.case_id}"},
            "recursion_limit": 200,
        }
        builder = build_graph()
        worker = get_current_worker()
        log.case_start(self.case_id)

        try:
            if self.backend == "sqlite":
                from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
                path = os.getenv("SIFT_SQLITE_PATH", "./sift_checkpoints.sqlite")
                async with AsyncSqliteSaver.from_conn_string(path) as saver:
                    graph = builder.compile(checkpointer=saver)
                    await self._drive(graph, initial, config, worker)
            else:
                from langgraph.checkpoint.memory import MemorySaver
                graph = builder.compile(checkpointer=MemorySaver())
                await self._drive(graph, initial, config, worker)
        except Exception as exc:  # surface, don't crash the UI
            log.error("tui", f"run failed: {exc}")
            self.sub_title = "ERROR"
            return

        log.case_done(self.case_id)
        self.sub_title = "COMPLETE"
        self._update_status()

    async def _drive(self, graph, initial, config, worker) -> None:
        async for state in graph.astream(initial, config, stream_mode="values"):
            if worker.is_cancelled:
                return
            self._final_state = state
            self._apply_state(state)

    # -- state snapshot -> panels --------------------------------------- #
    def _apply_state(self, state: dict) -> None:
        phase = state.get("phase") or ""
        if phase and phase != self._phase:
            self._phase = phase
            self.query_one("#phasebar", Static).update(self._phase_bar())
        self._render_findings(state.get("findings") or [])
        self._render_evidence(state.get("evidence") or [])
        self._update_status()

    def _render_findings(self, findings: list[dict]) -> None:
        table = self.query_one("#findings", DataTable)
        for f in findings:
            fid = f.get("id", "?")
            conf = f.get("confidence", "weak")
            row = [
                fid,
                (f.get("claim") or "")[:48],
                f"{_CONF_DOT.get(conf, '○')} {conf}",
                ",".join(f.get("attack_techniques") or []) or "-",
            ]
            if fid in self._finding_rows:
                self._replace_row(table, fid, row)
            else:
                table.add_row(*row, key=fid)
                self._finding_rows.add(fid)

    def _render_evidence(self, evidence: list[dict]) -> None:
        table = self.query_one("#evidence", DataTable)
        for e in evidence:
            path = e.get("path", "?")
            row = [
                (Path(path).name or path)[:30],
                "✓" if e.get("sha256") else "…",
                "✓" if (e.get("chain_of_custody") or []) else "…",
            ]
            if path in self._evidence_rows:
                self._replace_row(table, path, row)
            else:
                table.add_row(*row, key=path)
                self._evidence_rows.add(path)

    @staticmethod
    def _replace_row(table: DataTable, key: str, row: list) -> None:
        try:
            for col_key, val in zip(table.columns.keys(), row):
                table.update_cell(key, col_key, val)
        except Exception:
            pass

    # -- logger events -> agents panel + tool stream -------------------- #
    def on_log_message(self, message: LogMessage) -> None:
        ev = message.event
        if ev.kind == "agent_start":
            self._upsert_agent(ev.who, status="run")
            self._write(f"[green][Agent][/] [b]{ev.who}[/] - {ev.msg}")
        elif ev.kind == "agent_done":
            self._upsert_agent(
                ev.who, status="done", tok_in=ev.tokens_in, tok_out=ev.tokens_out
            )
            self._update_status()
        elif ev.kind == "tool":
            failed = ev.exit_code not in (None, 0)
            color = "red" if failed else "yellow"
            tail = ""
            if ev.exit_code is not None:
                tail += f" exit={ev.exit_code}"
            if ev.duration_ms is not None:
                tail += f" {ev.duration_ms}ms"
            self._write(f"[{color}][Tool][/] [dim]{ev.who}[/] [b]{ev.tool}[/]{tail}")
            self._bump_agent_tools(ev.who)
        elif ev.kind == "gate":
            color = "magenta" if ev.decision == "ok" else "red"
            self._write(f"[magenta][Gate][/] [b]{ev.who}[/] -> [{color}]{ev.decision}[/]")
        elif ev.kind == "error":
            self._write(f"[red][Error][/] [b]{ev.who}[/] {ev.msg}")
            self._upsert_agent(ev.who, status="error")
        elif ev.kind == "info":
            self._write(f"[blue][Info][/] [dim]{ev.who}[/] {ev.msg}")
        elif ev.kind == "phase":
            self._write(f"[cyan][Phase][/] [b]{ev.msg}[/]")

    def _write(self, text: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.query_one("#tools", RichLog).write(f"[dim]{ts}[/] {text}")

    def _upsert_agent(
        self, name: str, status: str = "idle",
        tok_in: int | None = None, tok_out: int | None = None,
    ) -> None:
        table = self.query_one("#agents", DataTable)
        icon = _STATUS_ICON.get(status, "·")
        if name not in self._agent_rows:
            table.add_row(icon, name, "0", "0", "0", key=name)
            self._agent_rows.add(name)
            return
        cols = list(table.columns.keys())
        table.update_cell(name, cols[0], icon)
        if tok_in is not None:
            table.update_cell(name, cols[3], str(self._cell_int(table, name, cols[3]) + tok_in))
        if tok_out is not None:
            table.update_cell(name, cols[4], str(self._cell_int(table, name, cols[4]) + tok_out))

    def _bump_agent_tools(self, name: str) -> None:
        if name not in self._agent_rows:
            self._upsert_agent(name, status="run")
        table = self.query_one("#agents", DataTable)
        col = list(table.columns.keys())[2]
        table.update_cell(name, col, str(self._cell_int(table, name, col) + 1))

    @staticmethod
    def _cell_int(table: DataTable, row_key: str, col_key) -> int:
        try:
            return int(table.get_cell(row_key, col_key))
        except Exception:
            return 0

    # -- footer / phase bar / actions ----------------------------------- #
    def _update_status(self) -> None:
        t = log.totals()
        self.query_one("#status", Static).update(
            f"[b]tokens[/] in {t['tokens_in']:,} / out {t['tokens_out']:,}   "
            f"[b]tools[/] {t['tools']}   [b]errors[/] {t['errors']}   "
            f"[b]est[/] ${t['cost']:.4f}   "
            f"[dim]q quit · e export · c clear[/]"
        )

    def _phase_bar(self) -> str:
        return "  ▸  ".join(
            f"[reverse b] {p} [/]" if p == self._phase else f"[dim]{p}[/]"
            for p in PHASES
        )

    def action_clear_log(self) -> None:
        self.query_one("#tools", RichLog).clear()

    def action_export(self) -> None:
        out_dir = Path(os.getenv("SIFT_REPORTS_DIR", "./reports"))
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{self.case_id}.snapshot.json"
        path.write_text(
            json.dumps(self._final_state or {}, indent=2, default=str),
            encoding="utf-8",
        )
        self._write(f"[green][Export][/] wrote {path}")

    def on_unmount(self) -> None:
        try:
            log.remove_sink(self._sink)
            log.use_console(True)
        except Exception:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(prog="sift-tui")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--evidence", required=True, nargs="+")
    parser.add_argument(
        "--backend",
        default=os.getenv("SIFT_CHECKPOINT_BACKEND", "memory"),
        choices=["memory", "sqlite"],
        help="Checkpoint backend (memory is simplest for a live run)",
    )
    args = parser.parse_args()
    SiftTUI(args.case_id, args.evidence, args.backend).run()


if __name__ == "__main__":
    main()
