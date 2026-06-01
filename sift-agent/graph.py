from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from gates import gate_attribution_ok, gate_hash_ok, halt_handler
from routers import analysis_router, pick_specialists
from state import CaseState
from synthesizer import synthesizer_node
from workers import (
    acquirer_node, attack_map_node, carver_node, crypto_node,
    defense_map_node, filesystem_node, hasher_node, malware_static_node,
    memory_node, network_node, reversing_node, windows_node,
)

SPECIALIST_NODES = [
    "filesystem", "carve", "windows", "memory",
    "network", "malware_static", "reversing", "crypto",
]


def build_graph() -> StateGraph:
    g = StateGraph(CaseState)

    g.add_node("acquire",        acquirer_node)
    g.add_node("hash",           hasher_node)
    g.add_node("analyze",        analysis_router)
    g.add_node("filesystem",     filesystem_node)
    g.add_node("carve",          carver_node)
    g.add_node("windows",        windows_node)
    g.add_node("memory",         memory_node)
    g.add_node("network",        network_node)
    g.add_node("malware_static", malware_static_node)
    g.add_node("reversing",      reversing_node)
    g.add_node("crypto",         crypto_node)
    g.add_node("attack_map",     attack_map_node)
    g.add_node("defense_map",    defense_map_node)
    g.add_node("report",         synthesizer_node)
    g.add_node("halt",           halt_handler)

    g.add_edge(START, "acquire")
    g.add_edge("acquire", "hash")

    g.add_conditional_edges(
        "hash", gate_hash_ok, {"ok": "analyze", "fail": "halt"},
    )

    g.add_conditional_edges("analyze", pick_specialists, SPECIALIST_NODES)
    for n in SPECIALIST_NODES:
        g.add_edge(n, "attack_map")

    g.add_edge("attack_map", "defense_map")
    g.add_conditional_edges(
        "defense_map", gate_attribution_ok, {"ok": "report", "fail": "halt"},
    )

    g.add_edge("report", END)
    g.add_edge("halt", END)
    return g
