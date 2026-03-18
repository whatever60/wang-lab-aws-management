# AWS Inventory Join Tables

Small CLI app that generates two joined tables from fresh AWS metadata via AWS CLI:

1. `instance-volume-table`
1. `snapshot-audit-table`

Pricing is fetched from the AWS public pricing endpoint and cached for 24 hours by default at:

`.cache/aws-pricing/<region>.json`

## Requirements

- Python 3.9+
- AWS CLI installed and authenticated
- Region configured in AWS CLI or passed with `--region`

## Commands

### 1) Instance + Volume + Price table

Outer join of instances and volumes based on attached instances, with:

- EC2 on-demand price per hour
- EC2 estimated monthly price (`hourly * 730`)
- EBS storage monthly price (`size_gib * usd_per_gb_month`)

Sorted by:

1. `key_name`
1. `ec2_price_per_hour_usd`

Run:

```bash
python aws_inventory_tables.py instance-volume-table
```

Useful options:

```bash
python aws_inventory_tables.py --region us-east-1 instance-volume-table
python aws_inventory_tables.py --format csv instance-volume-table
python aws_inventory_tables.py instance-volume-table --no-price-cache
```

### 2) Snapshot audit table

Outer join across snapshots, volumes, and AMIs to highlight potentially dangling snapshots.

Each row includes:

- snapshot metadata
- whether the source volume still exists
- attached instance IDs (if source volume is attached)
- AMIs that reference the snapshot
- status tags such as `ATTACHED_VOLUME`, `USED_BY_AMI`, `EXISTING_VOLUME`, `DANGLING`

Sorted by snapshot size descending.

Run:

```bash
python aws_inventory_tables.py snapshot-audit-table
```

Useful options:

```bash
python aws_inventory_tables.py --region us-east-1 snapshot-audit-table
python aws_inventory_tables.py --format json snapshot-audit-table
```
