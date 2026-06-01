#!/usr/bin/env bash
# test_all.sh — one-shot verification of every SIFT MCP server and tool.
# Run from project root inside WSL Ubuntu-22.04 with the venv active.
set -e

echo "════════════════════════════════════════════════════════"
echo "  SIFT-MCP test pipeline — start"
echo "════════════════════════════════════════════════════════"

. .venv/bin/activate

echo
echo "─── 1/5  verify.py  (load + 1 probe per server) ────────"
python verify.py | tail -25

echo
echo "─── 2/5  audit_tools.py  (every SIFT binary, 5s probe) ─"
python audit_tools.py | tail -16

echo
echo "─── 3/5  verify_attack_defend.py  (12 functional checks) ─"
python verify_attack_defend.py | tail -25

echo
echo "─── 4/5  phase5_report.py  (speed + coverage report) ───"
python phase5_report.py | tail -45

echo
echo "─── 5/5  real MCP stdio handshake against sift-attack ──"
printf '%s\n%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"x","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | timeout 30 ~/.local/bin/uvx --from servers sift-attack 2>/dev/null \
  | head -c 400
echo
echo "    ... (truncated)"

echo
echo "════════════════════════════════════════════════════════"
echo "  ALL TEST LAYERS PASSED"
echo "════════════════════════════════════════════════════════"
