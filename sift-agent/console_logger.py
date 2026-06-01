from __future__ import annotations

import os
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

_USE_COLOR = (
    sys.stdout.isatty()
    and os.getenv("NO_COLOR") is None
    and os.getenv("SIFT_NO_COLOR") is None
)


class C:
    RESET   = "\033[0m"  if _USE_COLOR else ""
    DIM     = "\033[2m"  if _USE_COLOR else ""
    BOLD    = "\033[1m"  if _USE_COLOR else ""
    RED     = "\033[31m" if _USE_COLOR else ""
    GREEN   = "\033[32m" if _USE_COLOR else ""
    YELLOW  = "\033[33m" if _USE_COLOR else ""
    BLUE    = "\033[34m" if _USE_COLOR else ""
    MAGENTA = "\033[35m" if _USE_COLOR else ""
    CYAN    = "\033[36m" if _USE_COLOR else ""
    GRAY    = "\033[90m" if _USE_COLOR else ""


@dataclass
class WorkerStats:
    name: str
    tools_called: int = 0
    errors: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    started_at: str = ""
    finished_at: str = ""


@dataclass
class Event:
    """A single structured log event fanned out to every sink."""
    kind: str                      # case_start|case_done|phase|agent_start|
                                   # agent_done|tool|gate|error|info
    ts: str = ""
    who: str = ""                  # agent / tool owner / case id
    msg: str = ""                  # free text (doing / info / error)
    tool: str = ""
    exit_code: int | None = None
    duration_ms: int | None = None
    tokens_in: int = 0
    tokens_out: int = 0
    decision: str = ""             # for gate
    is_opus: bool = False


_HAIKU_IN  = 1.0   # $/M tokens
_HAIKU_OUT = 5.0
_OPUS_IN   = 15.0
_OPUS_OUT  = 75.0


class Sink(Protocol):
    """Anything that can consume log events (console, TUI, file, ...)."""
    def handle(self, ev: Event) -> None: ...


class ConsoleSink:
    """Default sink: the original colored stdout renderer."""

    def __init__(self) -> None:
        self._lock = threading.Lock()

    def _print(self, line: str) -> None:
        with self._lock:
            print(line, flush=True)

    def handle(self, ev: Event) -> None:
        t = f"{C.GRAY}[{ev.ts}]{C.RESET} "
        if ev.kind == "case_start":
            self._print(f"\n{C.BOLD}{C.CYAN}=== CASE {ev.who} ==={C.RESET}")
        elif ev.kind == "case_done":
            self._print(f"{C.BOLD}{C.CYAN}=== CASE {ev.who} COMPLETE ==={C.RESET}")
        elif ev.kind == "phase":
            self._print(f"{t}{C.CYAN}[Phase]{C.RESET}  {C.BOLD}{ev.msg}{C.RESET}")
        elif ev.kind == "agent_start":
            self._print(
                f"{t}{C.GREEN}[Agent]{C.RESET} {C.BOLD}{ev.who:<16}{C.RESET} "
                f"{C.DIM}-{C.RESET} {ev.msg}"
            )
        elif ev.kind == "agent_done":
            self._print(
                f"{t}{C.GREEN}[Agent]{C.RESET} {C.BOLD}{ev.who:<16}{C.RESET} "
                f"{C.DIM}done   tokens in:{ev.tokens_in} out:{ev.tokens_out}{C.RESET}"
            )
        elif ev.kind == "tool":
            failed = ev.exit_code is not None and ev.exit_code != 0
            tail = ""
            if ev.exit_code is not None:
                tail += f"  exit={ev.exit_code}"
            if ev.duration_ms is not None:
                tail += f"  duration={ev.duration_ms}ms"
            color = C.RED if failed else C.YELLOW
            self._print(
                f"{t}{color}[Tool]{C.RESET}   {C.DIM}{ev.who:<16}{C.RESET} "
                f"{C.BOLD}{ev.tool:<28}{C.RESET}{C.DIM}{tail}{C.RESET}"
            )
        elif ev.kind == "gate":
            color = C.MAGENTA if ev.decision == "ok" else C.RED
            self._print(
                f"{t}{C.MAGENTA}[Gate]{C.RESET}   {C.BOLD}{ev.who:<16}{C.RESET} "
                f"-> {color}{ev.decision}{C.RESET}"
            )
        elif ev.kind == "error":
            self._print(
                f"{t}{C.RED}[Error]{C.RESET}  {C.BOLD}{ev.who:<16}{C.RESET} {ev.msg}"
            )
        elif ev.kind == "info":
            self._print(
                f"{t}{C.BLUE}[Info]{C.RESET}   {C.BOLD}{ev.who:<16}{C.RESET} {ev.msg}"
            )


class Logger:
    """
    Event dispatcher. Keeps the same public API the workers/gates/run.py
    already call, but fans each call out to one or more sinks. By default
    it prints to the console; a TUI registers its own sink and silences
    the console with `use_console(False)`.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.stats: dict[str, WorkerStats] = {}
        self.opus_agents: set[str] = set()
        self.current_phase: str = ""
        self._console = ConsoleSink()
        self._sinks: list[Sink] = [self._console]

    # -- sink management -------------------------------------------------
    def add_sink(self, sink: Sink) -> None:
        with self._lock:
            self._sinks.append(sink)

    def remove_sink(self, sink: Sink) -> None:
        with self._lock:
            self._sinks = [s for s in self._sinks if s is not sink]

    def use_console(self, enabled: bool) -> None:
        with self._lock:
            has = self._console in self._sinks
            if enabled and not has:
                self._sinks.insert(0, self._console)
            elif not enabled and has:
                self._sinks = [s for s in self._sinks if s is not self._console]

    # -- dispatch --------------------------------------------------------
    @staticmethod
    def _ts() -> str:
        return datetime.now().strftime("%H:%M:%S")

    def _emit(self, ev: Event) -> None:
        for s in list(self._sinks):
            try:
                s.handle(ev)
            except Exception:
                pass

    # -- public API (unchanged signatures) -------------------------------
    def case_start(self, case_id: str) -> None:
        self._emit(Event("case_start", self._ts(), who=case_id))

    def case_done(self, case_id: str) -> None:
        self._emit(Event("case_done", self._ts(), who=case_id))

    def phase(self, phase: str) -> None:
        self.current_phase = phase
        self._emit(Event("phase", self._ts(), msg=phase))

    def mark_opus(self, name: str) -> None:
        self.opus_agents.add(name)

    def agent_start(self, name: str, doing: str) -> None:
        s = self.stats.setdefault(name, WorkerStats(name=name))
        if not s.started_at:
            s.started_at = self._ts()
        self._emit(Event(
            "agent_start", self._ts(), who=name, msg=doing,
            is_opus=name in self.opus_agents,
        ))

    def agent_done(self, name: str, tokens_in: int = 0, tokens_out: int = 0) -> None:
        s = self.stats.setdefault(name, WorkerStats(name=name))
        s.input_tokens += tokens_in
        s.output_tokens += tokens_out
        s.finished_at = self._ts()
        self._emit(Event(
            "agent_done", self._ts(), who=name,
            tokens_in=tokens_in, tokens_out=tokens_out,
            is_opus=name in self.opus_agents,
        ))

    def tool(
        self,
        agent: str,
        tool: str,
        exit_code: int | None = None,
        duration_ms: int | None = None,
    ) -> None:
        s = self.stats.setdefault(agent, WorkerStats(name=agent))
        s.tools_called += 1
        if exit_code is not None and exit_code != 0:
            s.errors += 1
        self._emit(Event(
            "tool", self._ts(), who=agent, tool=tool,
            exit_code=exit_code, duration_ms=duration_ms,
        ))

    def gate(self, name: str, decision: str) -> None:
        self._emit(Event("gate", self._ts(), who=name, decision=decision))

    def error(self, who: str, msg: str) -> None:
        s = self.stats.setdefault(who, WorkerStats(name=who))
        s.errors += 1
        self._emit(Event("error", self._ts(), who=who, msg=msg))

    def info(self, who: str, msg: str) -> None:
        self._emit(Event("info", self._ts(), who=who, msg=msg))

    # -- cost helpers (shared by console summary and TUI footer) ---------
    def totals(self) -> dict:
        total_in = total_out = total_tools = total_err = 0
        cost = 0.0
        for s in self.stats.values():
            total_in += s.input_tokens
            total_out += s.output_tokens
            total_tools += s.tools_called
            total_err += s.errors
            in_rate  = _OPUS_IN  if s.name in self.opus_agents else _HAIKU_IN
            out_rate = _OPUS_OUT if s.name in self.opus_agents else _HAIKU_OUT
            cost += (s.input_tokens / 1_000_000) * in_rate
            cost += (s.output_tokens / 1_000_000) * out_rate
        return {
            "tokens_in": total_in, "tokens_out": total_out,
            "tools": total_tools, "errors": total_err, "cost": cost,
        }

    def summary(self) -> None:
        if not self.stats:
            return
        out = []
        out.append(f"\n{C.BOLD}{C.CYAN}=== SUMMARY ==={C.RESET}")
        out.append(
            f"{C.DIM}{'AGENT':<18} {'IN':>10} {'OUT':>10} "
            f"{'TOOLS':>8} {'ERR':>5}{C.RESET}"
        )
        for s in self.stats.values():
            out.append(
                f"{s.name:<18} {s.input_tokens:>10} {s.output_tokens:>10} "
                f"{s.tools_called:>8} {s.errors:>5}"
            )
        t = self.totals()
        out.append(
            f"{C.BOLD}{'TOTAL':<18} {t['tokens_in']:>10} {t['tokens_out']:>10} "
            f"{t['tools']:>8} {t['errors']:>5}{C.RESET}   "
            f"{C.DIM}cost~${t['cost']:.4f}{C.RESET}"
        )
        print("\n".join(out), flush=True)


# Backwards-compatible singleton + alias.
log = Logger()
ConsoleLogger = Logger  # legacy name
