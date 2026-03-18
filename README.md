# AWS Inventory Join Tables

Small CLI app that generates two joined tables from fresh AWS metadata via AWS CLI:

1. `instance-volume-table`
1. `snapshot-audit-table`

Pricing is fetched from the AWS public pricing endpoint and cached for 24 hours by default at:

`.cache/aws-pricing/<region>.json`

## Requirements

- Python 3.9+
- `uv`
- AWS CLI installed and authenticated (`v2` recommended; required for `chatbot` Slack setup)
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

## AWS Audit Setup Script

Create CloudTrail + EventBridge/SNS + AWS Config baseline with:

`setup_ec2_ebs_ami_audit.py`

Email mode:

```bash
python3 setup_ec2_ebs_ami_audit.py all \
  --alert-destination email \
  --email-endpoint "you@example.com"
```

Slack mode (auto-create or update Slack channel configuration, then link SNS topics):

```bash
python3 setup_ec2_ebs_ami_audit.py all \
  --alert-destination slack \
  --slack-channel-configuration-name "test-configuration" \
  --slack-team-id "T09CK3AAC" \
  --slack-channel-id "C0AMDBXTDHC" \
  --chatbot-region "us-west-2"
```

If `aws chatbot` endpoint errors in a region, switch `--chatbot-region` to one where `aws chatbot describe-slack-channel-configurations` succeeds.
In Slack mode, EventBridge targets are configured with an input transformer so messages are published in Amazon Q custom notification schema.

## Current Behavior Reference

### 1) What you should expect from Amazon Q in Slack (real use)

When a matching EC2 API activity happens, EventBridge sends a transformed message to SNS, and Amazon Q posts it to your configured Slack channel.

With the current rule, you get notifications for these EC2/EBS/AMI lifecycle API calls:

- `RunInstances`, `StartInstances`, `StopInstances`, `TerminateInstances`
- `CreateVolume`, `AttachVolume`, `DetachVolume`, `ModifyVolume`, `DeleteVolume`
- `CreateSnapshot`, `CreateSnapshots`, `CopySnapshot`, `DeleteSnapshot`, `ModifySnapshotAttribute`, `ModifySnapshotTier`, `RestoreSnapshotTier`
- `CreateImage`, `RegisterImage`, `CopyImage`, `DeregisterImage`, `ModifyImageAttribute`

### 2) General message format in Slack

Messages are custom-formatted (not raw JSON). In general, each message has:

- Title: `EC2/EBS/AMI API event: <eventName>`
- Description includes event name
- Description includes event source (`ec2.amazonaws.com`)
- Description includes detail type (`AWS API Call via CloudTrail`)
- Description includes account
- Description includes region
- Description includes event time
- Description includes actor ARN (who/what made the API call)
- Description includes instance type (when present in event payload)
- Description includes volume size in GiB (when present in event payload)
- Description includes volume type such as `gp3`/`gp2` (when present in event payload)
- Description includes snapshot tier such as `standard`/`archive` (when present in event payload)
- Description includes event ID
- Threading metadata keyed by account+region (`ec2-ebs-ami-audit-<account>-<region>`)

### 3) What CloudTrail is monitoring in this setup

CloudTrail is configured as a multi-Region trail with log file validation and S3 delivery.

Practically, this means:

- Account-level management API activity across enabled regions is logged to S3.
- This includes console, CLI, and SDK/API management actions.
- We did not configure data-event selectors here, so this setup focuses on management events.

### 4) What EventBridge is doing

EventBridge provides near-real-time filtering and routing:

- It listens for CloudTrail-backed EC2 API call events that match the event list above.
- It forwards matched events to regional SNS topics (`asset-audit-events`).
- In Slack mode, it applies an input transformer so SNS payloads are in Amazon Q custom notification schema.

### 5) What AWS Config is doing

AWS Config is set up per enabled region to track resource configuration history for:

- `AWS::EC2::Instance`
- `AWS::EC2::Volume`

It creates/uses recorder `default`, delivery channel `default`, and writes Config snapshots/history to the configured S3 bucket.

Run only one module:

```bash
python3 setup_ec2_ebs_ami_audit.py cloudtrail --base-region us-east-1
python3 setup_ec2_ebs_ami_audit.py events --alert-destination email --email-endpoint "you@example.com"
python3 setup_ec2_ebs_ami_audit.py slack --alert-destination slack --sns-topic-arns "arn:aws:sns:us-east-1:123456789012:asset-audit-events"
python3 setup_ec2_ebs_ami_audit.py config
```

Show all options:

```bash
python3 setup_ec2_ebs_ami_audit.py --help
```

Legacy shell script still exists as `setup_ec2_ebs_ami_audit.sh`.

Step-by-step rollout documentation (commands, resources created/used, verification):

- [AWS Audit Setup Runbook](docs/audit_setup_runbook.md)
