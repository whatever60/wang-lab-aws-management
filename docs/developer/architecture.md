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
tags; minimal account/region and cutover configuration lives in the Lambda environment.
Native EC2 creation is attributed from CloudTrail, and blank new-instance profiles
receive the verified creator's personal S3 role in the background. See
[member launch automation](../admin/member_launch_automation.md) for the trust
boundary, serialized event handling and lifecycle behavior.

## Keep One Implementation

The member controller has one CloudFormation definition. One EventBridge rule
handles IAM and successful EC2 creation events plus its five-minute repair
schedule. The Lambda uses native asynchronous retries, CloudWatch logs and an
error alarm; periodic reconciliation reads current state, so it does not need
an event replay queue. Nonsecret account/region
configuration fits in the Lambda environment and does not need an SSM lookup.
Unchanged state needs one resource scan; planned changes retain stale-plan and
grant-time identity/ownership checks.

The audit shell entry point delegates to the Python command. Retain independent
security boundaries: personal S3 roles isolate members' data writes; background
creator attribution and profile attachment preserve the normal AWS console and
CLI workflow. EC2 is allowed by default with explicit damage guardrails, not an
operation whitelist. IAM policy splitting exists
for AWS's document-size limit. Those resources perform distinct jobs.

CloudTrail/Config feed audit and historical cost allocation. Auto-stop alarms,
Slack audit enrichment, inventory reporting and optional HPC tooling also have
separate consumers. Keep them until a replacement preserves their behavior.

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
