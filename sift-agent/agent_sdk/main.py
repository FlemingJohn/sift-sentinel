import argparse
import asyncio

from audit_logger import AuditLogger
from investigation_controller import run_investigation


async def run_from_arguments(arguments):
    audit_logger = AuditLogger()
    await run_investigation(arguments.case_id, arguments.evidence, audit_logger)


def parse_arguments():
    parser = argparse.ArgumentParser(prog="sift-agent-sdk")
    parser.add_argument("--case-id", required=True)
    parser.add_argument(
        "--evidence",
        required=True,
        nargs="+",
        help="Evidence file paths accessible from inside the WSL distribution",
    )
    return parser.parse_args()


def main():
    arguments = parse_arguments()
    asyncio.run(run_from_arguments(arguments))


if __name__ == "__main__":
    main()
