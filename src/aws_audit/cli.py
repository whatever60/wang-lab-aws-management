"""Unified command-line entry point for the AWS audit repository."""

import argparse
import importlib
import sys
from typing import Optional


COMMAND_MODULES = {
    "audit-setup": "aws_audit.audit.setup",
    "hpc": "aws_audit.hpc.workflow",
    "inventory": "aws_audit.inventory.tables",
    "monthly-costs": "aws_audit.cost.monthly_compute",
    "s3-access": "aws_audit.s3_access.reconcile",
    "visual-check": "aws_audit.tools.check_visual_layout",
}


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level command parser."""
    parser = argparse.ArgumentParser(
        prog="aws-audit",
        description="Unified AWS audit, inventory, cost, S3 access, and HPC tooling.",
    )
    parser.add_argument(
        "command",
        choices=sorted(COMMAND_MODULES),
        help="Tool area to run. Add --help after the command for command-specific help.",
    )
    parser.add_argument(
        "args",
        nargs=argparse.REMAINDER,
        help="Arguments passed through to the selected command.",
    )
    return parser


def run_module_main(command: str, args: list[str]) -> int:
    """Run a selected module's main function with command-specific argv."""
    module = importlib.import_module(COMMAND_MODULES[command])
    original_argv = sys.argv
    sys.argv = [f"aws-audit {command}", *args]
    try:
        result = module.main()
    finally:
        sys.argv = original_argv
    if result is None:
        return 0
    return int(result)


def main(argv: Optional[list[str]] = None) -> int:
    """Run the unified CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return run_module_main(args.command, args.args)


if __name__ == "__main__":
    sys.exit(main())
