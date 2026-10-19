#!/usr/bin/env bash
# Keep one audit implementation; this entry point forwards flags to the CLI.
set -euo pipefail
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="${repo_dir}/src${PYTHONPATH:+:${PYTHONPATH}}"
exec "${AWS_AUDIT_PYTHON:-python3}" -m aws_audit.audit.setup "$@"
