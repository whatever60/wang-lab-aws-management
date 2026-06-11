# Code Architecture

The repo is organized as a Python package under `src/aws_audit`.

```text
src/aws_audit/
  cli.py
  audit/
  cost/
  hpc/
  inventory/
  s3_access/
  tools/
```

## Unified CLI

`pyproject.toml` exposes one console script:

```bash
uv run aws-audit --help
```

The top-level command dispatches to domain modules:

```text
aws-audit audit-setup    -> aws_audit.audit.setup
aws-audit hpc            -> aws_audit.hpc.workflow
aws-audit inventory      -> aws_audit.inventory.tables
aws-audit monthly-costs  -> aws_audit.cost.monthly_compute
aws-audit s3-access      -> aws_audit.s3_access.reconcile
aws-audit visual-check   -> aws_audit.tools.check_visual_layout
```

The dispatcher is intentionally thin. Each domain module keeps its own parser and
implementation.

## Generated Files

Generated operational files are ignored. Prefer regenerating them from committed
manifests and code instead of committing live account output.

Examples:

- ParallelCluster YAML
- active instance type allowlists
- catalog snapshots
- report outputs
- built docs under `site/`

## Sensitive Values

Committed code and docs should not contain account-specific values such as account IDs,
bucket names, ARNs, subnets, key names, IP allowlists, Slack IDs, or real rosters.

Use environment variables or ignored local manifests for real deployments.
