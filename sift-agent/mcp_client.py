from __future__ import annotations

import os

from langchain_mcp_adapters.client import MultiServerMCPClient

from tool_partition import WORKER_TOOLS

_USE_WSL = os.getenv("SIFT_USE_WSL", "1") == "1"
_WSL_DISTRO = os.getenv("SIFT_WSL_DISTRO", "Ubuntu-22.04")
_UVX = os.getenv("SIFT_UVX_PATH", "/home/user/.local/bin/uvx")
_SERVERS_DIR = os.getenv(
    "SIFT_SERVERS_DIR",
    "/mnt/c/Users/FlemingJohn/Downloads/sift-mcp-servers/servers",
)


def _stdio(server: str) -> dict:
    if _USE_WSL:
        return {
            "command": "wsl.exe",
            "args": [
                "-d", _WSL_DISTRO, "--",
                _UVX, "--from", _SERVERS_DIR, server,
            ],
            "transport": "stdio",
        }
    return {
        "command": "uvx",
        "args": ["--from", _SERVERS_DIR, server],
        "transport": "stdio",
    }


SERVERS = {
    "sift-attack":  _stdio("sift-attack"),
    "sift-defend":  _stdio("sift-defend"),
    "sift-disk":    _stdio("sift-disk"),
    "sift-windows": _stdio("sift-windows"),
    "sift-network": _stdio("sift-network"),
    "sift-memory":  _stdio("sift-memory"),
    "sift-hashing": _stdio("sift-hashing"),
    "sift-malware": _stdio("sift-malware"),
    "sift-crypto":  _stdio("sift-crypto"),
}


_client: MultiServerMCPClient | None = None
_all_tools_cache: list | None = None


async def get_client() -> MultiServerMCPClient:
    global _client
    if _client is None:
        _client = MultiServerMCPClient(SERVERS)
    return _client


async def get_all_tools() -> list:
    global _all_tools_cache
    if _all_tools_cache is None:
        client = await get_client()
        _all_tools_cache = await client.get_tools()
    return _all_tools_cache


async def get_tools_for_worker(worker: str) -> list:
    whitelist = WORKER_TOOLS.get(worker)
    if whitelist is None:
        raise KeyError(f"unknown worker scope: {worker}")
    all_tools = await get_all_tools()
    return [t for t in all_tools if t.name in whitelist]
