import os


WSL_DISTRIBUTION = os.getenv("SIFT_WSL_DISTRIBUTION", "Ubuntu-22.04")

MCP_SERVERS_DIRECTORY = os.getenv(
    "SIFT_MCP_SERVERS_DIRECTORY",
    "/mnt/c/Users/FlemingJohn/Downloads/SIFT - Sentinel/sift-mcp-servers/servers",
)

WORKER_MODEL_NAME = os.getenv("SIFT_WORKER_MODEL", "haiku")

SUPERVISOR_MODEL_NAME = os.getenv("SIFT_SUPERVISOR_MODEL", "opus")

REPORTS_DIRECTORY = os.getenv("SIFT_REPORTS_DIRECTORY", "./reports")

AUDIT_LOG_DIRECTORY = os.getenv("SIFT_AUDIT_LOG_DIRECTORY", "./logs")

MAXIMUM_TURNS_PER_SPECIALIST = int(os.getenv("SIFT_MAXIMUM_TURNS_PER_SPECIALIST", "40"))

MAXIMUM_BUDGET_USD = float(os.getenv("SIFT_MAXIMUM_BUDGET_USD", "5.0"))
