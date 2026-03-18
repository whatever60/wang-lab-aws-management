# AWS Inventory Join Tables

Small CLI app that generates two joined tables from fresh AWS metadata via AWS CLI:

1. `instance-volume-table`
1. `snapshot-audit-table`

Pricing is fetched from the AWS public pricing endpoint and cached for 24 hours by default at:

`.cache/aws-pricing/<region>.json`

## Requirements

- Python 3.9+
- `uv`
- AWS CLI installed and authenticated
- Region configured in AWS CLI or passed with `--region`

Install dependencies:

```bash
uv sync
```

## Commands

### 1) Instance + Volume + Price table

Outer join of instances and volumes based on attached instances, with:

- resource `Name` tags (`instance_name`, `volume_name`)
- EC2 on-demand price per hour
- EC2 estimated monthly price (`hourly * 730`)
- EBS storage monthly price (`size_gib * usd_per_gb_month`)

Sorted by:

1. `key_name`
1. `ec2_price_per_hour_usd`

Run:

```bash
uv run python aws_inventory_tables.py instance-volume-table
```

Useful options:

```bash
uv run python aws_inventory_tables.py --region us-east-1 instance-volume-table
uv run python aws_inventory_tables.py --format csv instance-volume-table
uv run python aws_inventory_tables.py instance-volume-table --no-price-cache
uv run python aws_inventory_tables.py instance-volume-table --output outputs/instance_volume_table.xlsx
```

### 2) Snapshot audit table

Outer join across snapshots, volumes, and AMIs to highlight potentially dangling snapshots.

Each row includes:

- snapshot metadata
- resource `Name` tags (`snapshot_name`, `volume_name`)
- snapshot storage class (`standard` or `archive`)
- whether the source volume still exists
- attached instance IDs (if source volume is attached)
- AMIs that reference the snapshot (`ami_ids`) and their names (`ami_names`)
- status tags such as `ATTACHED_VOLUME`, `USED_BY_AMI`, `EXISTING_VOLUME`, `DANGLING`

Sorted by snapshot size descending.

Run:

```bash
uv run python aws_inventory_tables.py snapshot-audit-table
```

Useful options:

```bash
uv run python aws_inventory_tables.py --region us-east-1 snapshot-audit-table
uv run python aws_inventory_tables.py --format json snapshot-audit-table
uv run python aws_inventory_tables.py snapshot-audit-table --output outputs/snapshot_audit_table.xlsx
```

`--output` auto-detects format from file extension:

- `.csv`
- `.json`
- `.xlsx`
- `.txt` / `.table`
