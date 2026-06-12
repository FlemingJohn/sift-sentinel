import json
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime

from configuration import AUDIT_LOG_DIRECTORY


HAIKU_INPUT_RATE_PER_MILLION = 1.0
HAIKU_OUTPUT_RATE_PER_MILLION = 5.0
OPUS_INPUT_RATE_PER_MILLION = 15.0
OPUS_OUTPUT_RATE_PER_MILLION = 75.0


@dataclass
class SpecialistStatistics:
    name: str
    tools_called: int = 0
    errors: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0


@dataclass
class AuditLogger:
    case_id: str = ""
    statistics: dict = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)
    audit_file_path: str = ""

    def open_case(self, case_id):
        self.case_id = case_id
        os.makedirs(AUDIT_LOG_DIRECTORY, exist_ok=True)
        self.audit_file_path = os.path.join(AUDIT_LOG_DIRECTORY, f"{case_id}.jsonl")
        self.write_record("case_started", {"case_id": case_id})
        self.print_line(f"CASE {case_id} started")

    def close_case(self):
        self.write_record("case_completed", {"case_id": self.case_id})
        self.print_line(f"CASE {self.case_id} completed")

    def phase_changed(self, phase_name):
        self.write_record("phase_changed", {"phase": phase_name})
        self.print_line(f"PHASE {phase_name}")

    def specialist_started(self, specialist_name, description):
        self.write_record("specialist_started", {
            "specialist": specialist_name,
            "description": description,
        })
        self.print_line(f"SPECIALIST {specialist_name} started: {description}")

    def specialist_completed(self, specialist_name, input_tokens, output_tokens,
                             cost_usd, is_supervisor):
        statistics = self.statistics_for(specialist_name)
        statistics.input_tokens += input_tokens
        statistics.output_tokens += output_tokens
        statistics.cost_usd += cost_usd
        self.write_record("specialist_completed", {
            "specialist": specialist_name,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd": cost_usd,
        })
        self.print_line(
            f"SPECIALIST {specialist_name} completed "
            f"input_tokens={input_tokens} output_tokens={output_tokens} "
            f"cost_usd={cost_usd:.4f}"
        )

    def tool_invoked(self, specialist_name, tool_name, exit_code, duration_ms):
        statistics = self.statistics_for(specialist_name)
        statistics.tools_called += 1
        if exit_code is not None and exit_code != 0:
            statistics.errors += 1
        self.write_record("tool_invoked", {
            "specialist": specialist_name,
            "tool": tool_name,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
        })
        self.print_line(
            f"TOOL {specialist_name} {tool_name} "
            f"exit_code={exit_code} duration_ms={duration_ms}"
        )

    def gate_evaluated(self, gate_name, decision):
        self.write_record("gate_evaluated", {"gate": gate_name, "decision": decision})
        self.print_line(f"GATE {gate_name} {decision}")

    def tool_denied(self, specialist_name, tool_name, reason):
        self.write_record("tool_denied", {
            "specialist": specialist_name,
            "tool": tool_name,
            "reason": reason,
        })
        self.print_line(f"DENY {specialist_name} {tool_name}: {reason}")

    def error_occurred(self, source, message):
        statistics = self.statistics_for(source)
        statistics.errors += 1
        self.write_record("error", {"source": source, "message": message})
        self.print_line(f"ERROR {source}: {message}")

    def information(self, source, message):
        self.write_record("information", {"source": source, "message": message})
        self.print_line(f"INFO {source}: {message}")

    def statistics_for(self, specialist_name):
        if specialist_name not in self.statistics:
            self.statistics[specialist_name] = SpecialistStatistics(name=specialist_name)
        return self.statistics[specialist_name]

    def total_cost_usd(self):
        return sum(statistics.cost_usd for statistics in self.statistics.values())

    def print_summary(self):
        self.print_line("SUMMARY")
        for statistics in self.statistics.values():
            self.print_line(
                f"  {statistics.name} "
                f"input_tokens={statistics.input_tokens} "
                f"output_tokens={statistics.output_tokens} "
                f"tools={statistics.tools_called} "
                f"errors={statistics.errors} "
                f"cost_usd={statistics.cost_usd:.4f}"
            )
        self.print_line(f"  TOTAL cost_usd={self.total_cost_usd():.4f}")

    def write_record(self, kind, payload):
        if not self.audit_file_path:
            return
        record = {
            "timestamp": datetime.now().isoformat(),
            "kind": kind,
            "payload": payload,
        }
        with self.lock:
            with open(self.audit_file_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record) + "\n")

    def print_line(self, line):
        with self.lock:
            print(line, flush=True)


def estimate_cost_usd(input_tokens, output_tokens, is_supervisor):
    if is_supervisor:
        input_rate = OPUS_INPUT_RATE_PER_MILLION
        output_rate = OPUS_OUTPUT_RATE_PER_MILLION
    else:
        input_rate = HAIKU_INPUT_RATE_PER_MILLION
        output_rate = HAIKU_OUTPUT_RATE_PER_MILLION
    return (input_tokens / 1_000_000) * input_rate + (output_tokens / 1_000_000) * output_rate
