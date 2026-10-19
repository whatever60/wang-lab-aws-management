# Code Architecture

The repo is organized as a Python package under `src/aws_audit`.

```text
src/aws_audit/
  cli.py
  audit/
  cost/
  ec2_access/
  hpc/
  inventory/
  member_access/
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
aws-audit member-access  -> aws_audit.member_access.cli
aws-audit monthly-costs  -> aws_audit.cost.monthly_compute
aws-audit s3-access      -> aws_audit.s3_access.reconcile
aws-audit visual-check   -> aws_audit.tools.check_visual_layout
```

The dispatcher is intentionally thin. Each domain module keeps its own parser and
implementation.

`member_access` separates configuration models, S3-only role policy state,
metadata reconciliation, the Lambda runtime and offline deployment rendering.
The deployed runtime derives members from IAM and home ownership from bucket
tags; the approved SSM configuration contains infrastructure only. It uses the
same launch-request and EC2 policy builders as the local tooling. See
[member launch automation](../admin/member_launch_automation.md) for the trust
boundary, serialized event handling and lifecycle behavior.

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
