from __future__ import annotations

import argparse
import asyncio
import os

from dotenv import load_dotenv

load_dotenv()

from console_logger import log
from graph import build_graph
from state import CaseState


_PHASE_NODES = {
    "acquire", "hash", "analyze", "filesystem", "carve", "windows",
    "memory", "network", "malware_static", "reversing",
    "crypto", "attack_map", "defense_map", "report", "halt",
}


async def _drive(graph, args) -> None:
    initial: CaseState = {
        "case_id": args.case_id,
        "evidence": [
            {"path": p, "chain_of_custody": []} for p in args.evidence
        ],
        "findings": [],
        "errors": [],
        "candidate_files": [],
    }
    config = {
        "configurable": {"thread_id": f"case-{args.case_id}"},
        "recursion_limit": 200,
    }

    log.case_start(args.case_id)
    last_phase = ""
    async for chunk in graph.astream(
        initial, config,
        stream_mode=["updates"], version="v2",
    ):
        if chunk["type"] != "updates":
            continue
        for node_name in chunk["data"].keys():
            if node_name in _PHASE_NODES and node_name != last_phase:
                log.phase(node_name)
                last_phase = node_name
    log.case_done(args.case_id)
    log.summary()


async def main_async() -> None:
    parser = argparse.ArgumentParser(prog="sift-agent")
    parser.add_argument("--case-id", required=True)
    parser.add_argument(
        "--evidence", required=True, nargs="+",
        help="Evidence file paths (must be accessible from inside WSL)",
    )
    args = parser.parse_args()

    builder = build_graph()
    backend = os.getenv("SIFT_CHECKPOINT_BACKEND", "sqlite").lower()

    if backend == "postgres":
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

        pg_url = os.environ["SIFT_PG_URL"]
        async with AsyncPostgresSaver.from_conn_string(pg_url) as saver:
            await saver.setup()
            graph = builder.compile(checkpointer=saver)
            await _drive(graph, args)
    elif backend == "memory":
        from langgraph.checkpoint.memory import MemorySaver

        graph = builder.compile(checkpointer=MemorySaver())
        await _drive(graph, args)
    else:
        from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

        sqlite_path = os.getenv("SIFT_SQLITE_PATH", "./sift_checkpoints.sqlite")
        async with AsyncSqliteSaver.from_conn_string(sqlite_path) as saver:
            graph = builder.compile(checkpointer=saver)
            await _drive(graph, args)


def main() -> None:
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
