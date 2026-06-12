from configuration import MCP_SERVERS_DIRECTORY, WSL_DISTRIBUTION
from tool_server_map import TOOL_SERVER_NAMES


def server_file_name(server_name):
    return server_name.replace("-", "_") + ".py"


def server_stdio_configuration(server_name):
    script_path = f"{MCP_SERVERS_DIRECTORY}/{server_file_name(server_name)}"
    return {
        "command": "wsl.exe",
        "args": [
            "-d", WSL_DISTRIBUTION, "--",
            "python3", script_path,
        ],
    }


def servers_for_tools(tool_names):
    server_names = []
    for tool_name in tool_names:
        server_name = TOOL_SERVER_NAMES.get(tool_name)
        if server_name and server_name not in server_names:
            server_names.append(server_name)
    return server_names


def build_server_configurations(server_names):
    return {
        server_name: server_stdio_configuration(server_name)
        for server_name in server_names
    }


def qualified_tool_names(tool_names):
    qualified = []
    for tool_name in tool_names:
        server_name = TOOL_SERVER_NAMES.get(tool_name)
        if server_name:
            qualified.append(f"mcp__{server_name}__{tool_name}")
    return qualified


def unqualified_tool_name(qualified_name):
    return qualified_name.split("__")[-1]


def server_name_from_qualified(qualified_name):
    parts = qualified_name.split("__")
    if len(parts) >= 3:
        return parts[1]
    return ""
