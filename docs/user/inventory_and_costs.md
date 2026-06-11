# Inventory And Cost Reports

The repo includes read-oriented commands for AWS inventory and EC2 compute cost
allocation.

## Inventory Tables

```bash
uv run aws-audit inventory instance-volume-table
uv run aws-audit inventory snapshot-audit-table
uv run aws-audit inventory ami-audit-table
```

Useful options:

```bash
uv run aws-audit inventory --region us-east-1 instance-volume-table
uv run aws-audit inventory --format csv snapshot-audit-table
uv run aws-audit inventory ami-audit-table --all-regions
```

Outputs can be written as CSV, JSON, table text, or XLSX depending on the command.

## Monthly Compute Cost Allocation

```bash
uv run aws-audit monthly-costs 2026-04 outputs/monthly_compute_2026-04
```

This allocates actual Cost Explorer EC2 compute cost to instances, key names, and
CloudTrail creator signals using AWS Config history. The result is an allocation model,
not direct per-instance billing from AWS.

## Caveats

- Savings Plans, Reserved Instances, credits, refunds, taxes, and support charges are not
  modeled separately.
- Creator attribution depends on CloudTrail retention.
- AWS Config must have recorded the instance state transitions.
