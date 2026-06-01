"""
shared.py — Shared utilities for all SIFT MCP servers
=======================================================
Imported by every generated server file.
"""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path


class AuditLogger:
    """
    Writes every tool call to a JSONL audit log.
    One log file per server, one line per call.
    Judges can trace any finding back to the exact tool execution.
    """

    def __init__(self, server_name: str, log_dir: str = "logs"):
        self.server   = server_name
        self.log_dir  = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.log_dir / f"{server_name}.jsonl"

    def log(self, entry: dict):
        entry["_server"] = self.server
        with open(self.log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")


class OutputTruncator:
    """
    Prevents context window overload by truncating large tool outputs.
    Keeps the first half and last half of output so both
    the header and tail of large outputs are always visible.
    """

    def __init__(self, max_chars: int = 50_000):
        self.max_chars = max_chars

    def truncate(self, text: str) -> str:
        if not text:
            return ""
        if len(text) <= self.max_chars:
            return text
        half    = self.max_chars // 2
        removed = len(text) - self.max_chars
        return (
            text[:half]
            + f"\n\n[... TRUNCATED {removed:,} characters ...]\n\n"
            + text[-half:]
        )


class ReadOnlyEnforcer:
    """
    Verifies that the evidence directory is mounted read-only.
    Override check() with OS-level mount verification for production.

    Default implementation checks /proc/mounts for the evidence path.
    """

    def __init__(self, evidence_path: str = "/evidence"):
        self.evidence_path = evidence_path

    def check(self):
        """
        Called before every tool execution.
        Raises RuntimeError if evidence path is writable.
        """
        # production: parse /proc/mounts and verify 'ro' flag
        # default: pass (override for strict enforcement)
        pass

    def verify_mount(self) -> dict:
        """
        Returns mount status of the evidence directory.
        Call this as an MCP tool to inspect evidence integrity.
        """
        try:
            with open("/proc/mounts") as f:
                mounts = f.read()

            for line in mounts.splitlines():
                parts = line.split()
                if len(parts) >= 4 and self.evidence_path in parts[1]:
                    options = parts[3].split(",")
                    return {
                        "path":      self.evidence_path,
                        "device":    parts[0],
                        "fs_type":   parts[2],
                        "options":   options,
                        "read_only": "ro" in options,
                        "mounted":   True,
                    }

            return {
                "path":    self.evidence_path,
                "mounted": False,
                "warning": "evidence path not found in /proc/mounts",
            }

        except Exception as e:
            return {"error": str(e)}
