# Wang Lab AWS Resource Management and Auditing

## Contents

- [Requirements](#requirements)
- [AWS Inventory Join Table](#aws-inventory-join-table)
  - [1) Instance + Volume + Price table](#1-instance--volume--price-table)
  - [2) Snapshot audit table](#2-snapshot-audit-table)
- [AWS Monthly EC2 Compute Cost Allocation](#aws-monthly-ec2-compute-cost-allocation)
- [AWS HPC Workflow MVP](#aws-hpc-workflow-mvp)
- [AWS Aduit Setup Script](#aws-aduit-setup-script)
  - [CLI Arguments Quick Reference](#cli-arguments-quick-reference)
  - [Step 1) CloudTrail Baseline (`cloudtrail`)](#step-1-cloudtrail-baseline-cloudtrail)
  - [Step 2) Event Filtering and SNS Routing (`events`)](#step-2-event-filtering-and-sns-routing-events)
  - [Step 3) AWS Config Recording (`config`)](#step-3-aws-config-recording-config)
  - [Step 4) Slack Binding (`slack`)](#step-4-slack-binding-slack)
  - [Step 5) Full Setup (`all`)](#step-5-full-setup-all)

## Requirements

- Python 3.9+
- `openpyxl` Python package (for `.xlsx` output)
- AWS CLI installed and authenticated (`v2` recommended; required for `chatbot` Slack setup)
- Region configured in AWS CLI or passed with `--region`

Install dependencies:

```bash
python3 -m pip install openpyxl
```

## AWS Inventory Join Table

Small CLI app that generates two joined tables from fresh AWS metadata via AWS CLI:

1. `instance-volume-table`
1. `snapshot-audit-table`

Pricing is fetched from the AWS public pricing endpoint and cached for 24 hours by default at:

`.cache/aws-pricing/<region>.json`

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
python3 aws_inventory_tables.py instance-volume-table
```

Useful options:

```bash
python3 aws_inventory_tables.py --region us-east-1 instance-volume-table
python3 aws_inventory_tables.py --format csv instance-volume-table
python3 aws_inventory_tables.py instance-volume-table --no-price-cache
python3 aws_inventory_tables.py instance-volume-table --output outputs/instance_volume_table.xlsx
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

Status tag meanings:

- `ATTACHED_VOLUME`: source `volume_id` exists and that volume is currently attached to at least one EC2 instance.
- `USED_BY_AMI`: snapshot is referenced by one or more AMI block device mappings.
- `EXISTING_VOLUME`: source `volume_id` exists but is not currently attached to any EC2 instance.
- `DANGLING`: none of the above conditions are true.

Notes:

- A snapshot can have multiple tags at once. For example, `ATTACHED_VOLUME,USED_BY_AMI` means the source volume is currently attached and the snapshot is also referenced by at least one AMI.
- This commonly happens when an AMI is created from an instance and the instance still exists.
- `ATTACHED_VOLUME` and `EXISTING_VOLUME` are mutually exclusive.

Run:

```bash
python3 aws_inventory_tables.py snapshot-audit-table
```

Useful options:

```bash
python3 aws_inventory_tables.py --region us-east-1 snapshot-audit-table
python3 aws_inventory_tables.py --format json snapshot-audit-table
python3 aws_inventory_tables.py snapshot-audit-table --output outputs/snapshot_audit_table.xlsx
```

`--output` auto-detects format from file extension:

- `.csv`
- `.json`
- `.xlsx`
- `.txt` / `.table`

## AWS Monthly EC2 Compute Cost Allocation

`aws_monthly_compute_costs.py` allocates actual AWS Cost Explorer EC2 instance-hour compute cost to EC2 instances and key names using AWS Config history.

Run:

```bash
python3 aws_monthly_compute_costs.py 2026-04 outputs/monthly_compute_2026-04
```

Or with `uv`:

```bash
uv run python aws_monthly_compute_costs.py 2026-04 outputs/monthly_compute_2026-04
```

Arguments:

- `month`: billing month as `YYYY-MM`
- `output_folder`: folder where CSV files will be written

Output files:

- `ec2_compute_by_key_<month>.csv`
- `ec2_compute_by_creator_<month>.csv`
- `ec2_compute_by_instance_<month>.csv`
- `ec2_compute_by_instance_interval_<month>.csv`
- `ec2_compute_type_reconciliation_<month>.csv`

Notes:

- Dollar totals come from AWS Cost Explorer `UnblendedCost`, not list price.
- Per-instance and per-key costs are allocated from Cost Explorer region/type totals in proportion to AWS Config running hours.
- Terminated instances are included when AWS Config recorded them.
- Creator ARN comes from CloudTrail `RunInstances` events when those events are still available. Older instances may show `unknown_cloudtrail_retention`.

### Method and Caveats

The CLI joins two different AWS data sources:

1. AWS Cost Explorer gives actual EC2 instance-hour compute dollars and billed hours grouped by `REGION` and `USAGE_TYPE`. EC2 instance usage appears as usage types like `BoxUsage:g6.4xlarge`.
1. AWS Config gives EC2 instance history, including instance type, key name, state changes, and deleted resources when Config recorded them.

Cost Explorer does not provide a built-in monthly cost grouped by EC2 key name or instance ID. To fill that gap, the script:

1. Finds all instances of each region and instance type that were running during the month.
1. Calculates each instance's AWS Config running hours for that month.
1. Allocates the Cost Explorer total for that same region/type across those instances in proportion to running hours.

For example, if Cost Explorer reports `$400` for `us-east-1` `g6.4xlarge`, and two instances ran for 100 and 300 hours, the script allocates `$100` and `$300`.

This means the total dollars are AWS billed dollars, but the per-instance and per-key split is an allocation. The main assumptions and limitations are:

- Same-region, same-type instance hours are treated as having the same effective hourly rate.
- The script does not separately model Savings Plans, Reserved Instances, credits, refunds, taxes, support charges, or other billing adjustments.
- Savings Plans and Reserved Instances can make true economic cost different from a simple instance-hour allocation, especially when benefits are shared across multiple users or instance families.
- CloudTrail creator ARN is best-effort only. EC2 instances do not store a durable creator ARN, so older instances may show `unknown_cloudtrail_retention`.
- AWS Config must have recorded the instance and its state history. Missing Config history can create `unattributed_config_history_gap` rows.

## AWS HPC Workflow MVP

This project now targets **AWS ParallelCluster + Slurm** for lab compute.

- Head/login node: one combined `r6a.xlarge` instance.
- Shared home: `EFS` at `/home`, deleted with the test cluster.
- Shared scratch: `FSx for Lustre SSD` at `/scratch`, deleted with the test cluster.
- Active user set is generated from IAM groups `lab_members` and `admin`, excluding `Diego_User`.
- Queues: CPU and GPU Slurm queues with `MinCount: 0`.
- Compute resources are generated from the live EC2 catalog and AWS Pricing API.
- The allowed catalog includes x86_64 and arm64 Linux instances, but the active test cluster is x86_64 because ParallelCluster requires one architecture across head, login, and compute nodes.
- Slurm jobs must specify explicit CPU and memory requests, or use `wanglab-sbatch --instance-type <type>` on the head/login node to request a concrete active EC2 instance type.

Reference docs:

- `docs/aws_hpc_workflow_proposal.md`
- `docs/aws_hpc_workflow_implementation.md`
- `docs/aws_parallelcluster_workflow.md`

Describe and preview the workflow:

```bash
uv run python aws_hpc_workflow.py describe
uv run python aws_hpc_workflow.py list-users
uv run python aws_hpc_workflow.py list-slurm-jobs
uv run python aws_hpc_workflow.py list-instance-catalog
uv run python aws_hpc_workflow.py list-instance-catalog --active-cluster-only
uv run python aws_hpc_workflow.py generate-config
uv run python aws_hpc_workflow.py generate-config --cluster-architecture arm64
uv run python aws_hpc_workflow.py execute-pcluster-dryrun
```

Create and delete the test cluster:

```bash
uv run python aws_hpc_workflow.py create-cluster
uv run python aws_hpc_workflow.py create-cluster --cluster-architecture arm64
uv run python aws_hpc_workflow.py delete-cluster
```

## AWS Aduit Setup Script

`setup_ec2_ebs_ami_audit.py` sets up CloudTrail, EventBridge/SNS, Slack binding, and AWS Config.

### CLI Arguments Quick Reference

Global defaults:

- `command`: `all` (choices: `all`, `cloudtrail`, `events`, `config`, `slack`)
- `--base-region`: `us-east-1`
- `--target-regions`: empty -> auto-resolve all enabled regions in the account
- `--alert-destination`: `email` (choices: `email`, `slack`)
- `--email-endpoint`: empty (required only for `events/all` when destination is `email`)

CloudTrail args:

- `--trail-name`: `account-audit-trail`
- `--trail-bucket`: empty -> defaults to `my-<account-id>-cloudtrail-audit`

EventBridge/SNS args:

- `--event-topic-name`: `asset-audit-events`
- `--rule-name`: `ec2-ebs-ami-audit`
- `--enricher-function-name`: `ec2-ebs-ami-audit-enricher`
- `--enricher-role-name`: `EC2EBSAMIAuditEnricherRole`
- `--enricher-source-path`: `ec2_audit_enricher_lambda.py`

AWS Config args:

- `--config-bucket`: empty -> defaults to `my-<account-id>-config-history`
- `--config-role-name`: `AWSConfigRecorderRole`
- `--config-recorder-name`: `default`
- `--config-delivery-channel-name`: `default`

Slack/Amazon Q args:

- `--chatbot-region`: empty -> uses `--base-region`
- `--slack-channel-configuration-name`: `test-configuration`
- `--slack-team-id`: `T09CK3AAC`
- `--slack-channel-id`: `C0AMDBXTDHC`
- `--slack-channel-name`: empty
- `--chatbot-role-name`: `ChatbotSlackRole`
- `--chatbot-role-arn`: empty (if set, script uses it directly)
- `--chatbot-role-policy-arn`: `arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess`
- `--chatbot-logging-level`: unset (`ERROR` is used only when creating a new Slack config)
- `--chatbot-guardrail-policy-arns`: empty (on create, defaults to `CloudWatchReadOnlyAccess`)
- `--chatbot-user-authorization-required`: unset (on create, defaults to `false`; on update, existing value is kept unless explicitly set)
- `--sns-topic-arns`: empty -> resolve/create per-region topics using `--event-topic-name`

### Step 1) CloudTrail Baseline (`cloudtrail`)

Command:

```bash
python3 setup_ec2_ebs_ami_audit.py cloudtrail \
  --base-region us-east-1 \
  --trail-name account-audit-trail
```

Key arguments:

- `--base-region` (default `us-east-1`): home region for trail API operations.
- `--trail-name` (default `account-audit-trail`): trail name.
- `--trail-bucket` (default `my-<account-id>-cloudtrail-audit`): optional override for CloudTrail S3 bucket name.

What this step does:

- Creates/reuses the trail bucket.
- Applies CloudTrail bucket policy.
- Creates or updates a multi-Region trail with log file validation.
- Starts logging.

Existing vs missing behavior:

- Trail S3 bucket:
  - Missing: created.
  - Existing and accessible: reused.
  - Existing but not creatable/reusable in your account: command fails.
- Trail bucket policy: always applied via `put-bucket-policy` (overwrites current bucket policy document with the script policy).
- CloudTrail trail:
  - Missing: `create-trail`.
  - Existing: `update-trail`.
- Logging: `start-logging` always runs.

What this step does not do:

- Does not configure CloudTrail data-event selectors.
- Does not send Slack/SNS notifications.

Effects:

- Writes CloudTrail event logs: `s3://my-787744166714-cloudtrail-audit/AWSLogs/787744166714/CloudTrail/<region>/YYYY/MM/DD/*.json.gz`
- Writes CloudTrail digest logs for integrity validation: `s3://my-787744166714-cloudtrail-audit/AWSLogs/787744166714/CloudTrail-Digest/<region>/YYYY/MM/DD/*.json.gz`
- Validation command example: `aws cloudtrail validate-logs --trail-arn arn:aws:cloudtrail:us-east-1:787744166714:trail/account-audit-trail --start-time 2026-03-18T00:00:00Z --region us-east-1`

### Step 2) Event Filtering and SNS Routing (`events`)

Command (Slack-oriented routing):

```bash
python3 setup_ec2_ebs_ami_audit.py events \
  --base-region us-east-1 \
  --alert-destination slack
```

Key arguments:

- `--target-regions` (default auto): optional explicit region list; defaults to enabled account regions.
- `--event-topic-name`: SNS topic name per region (default `asset-audit-events`).
- `--rule-name`: EventBridge rule name (default `ec2-ebs-ami-audit`).
- `--enricher-function-name`: Lambda function name used in Slack mode (default `ec2-ebs-ami-audit-enricher`).
- `--enricher-role-name`: Lambda execution role used in Slack mode (default `EC2EBSAMIAuditEnricherRole`).
- `--enricher-source-path`: local Lambda source file path used for deployment (default `ec2_audit_enricher_lambda.py`).
- `--alert-destination` (default `email`): `slack` or `email`.
- `--email-endpoint` (default empty): required if destination is `email`.

What this step does:

- Creates/reuses SNS topic in each target region.
- Creates/updates EventBridge rule for CloudTrail-backed EC2 API events.
- In `email` mode, sets SNS topic policy so EventBridge can publish and sets target `sns1` -> SNS.
- In `slack` mode, creates/updates Lambda enricher and sets target `enricher1` -> Lambda.
- In `slack` mode, Lambda queries EC2/Snapshot metadata and publishes Amazon Q custom notification JSON to SNS.

Existing vs missing behavior:

- SNS topic (`create-topic`):
  - Missing: created.
  - Existing: returned and reused.
- SNS email subscription:
  - Missing for that endpoint: created.
  - Existing: left as-is.
- SNS topic policy: set in `email` mode via `set-topic-attributes` (replaces topic `Policy` attribute with script policy).
- EventBridge rule (`put-rule`): create or update in place.
- EventBridge targets are reconciled each run: stale target IDs are removed, then desired target (`sns1` for email or `enricher1` for slack) is upserted.
- In `slack` mode, Lambda enricher role/function are create-or-update and Lambda invoke permission for EventBridge is ensured.

What this step does not do:

- Does not capture all CloudTrail events, only matching events.
- Does not write files to S3.

Filter behavior:

- Passes only events matching all of:
  - `source = aws.ec2`
  - `detail-type = AWS API Call via CloudTrail`
  - `detail.eventSource = ec2.amazonaws.com`
  - `detail.eventName` in configured allowlist (instance/volume/snapshot/AMI lifecycle calls).
- Current allowlist event names:
  - `RunInstances`, `StartInstances`, `StopInstances`, `TerminateInstances`
  - `CreateVolume`, `AttachVolume`, `DetachVolume`, `ModifyVolume`, `DeleteVolume`
  - `CreateSnapshot`, `CreateSnapshots`, `CopySnapshot`, `DeleteSnapshot`, `ModifySnapshotAttribute`, `ModifySnapshotTier`, `RestoreSnapshotTier`
  - `CreateImage`, `RegisterImage`, `CopyImage`, `DeregisterImage`, `ModifyImageAttribute`
- Non-matching management events are ignored by this rule.

Slack message format (consolidated):

- One custom message per matched event, titled `EC2/EBS/AMI API event: <eventName>`.
- Message body includes event/source/account/region/time/actor plus IDs (`instance`, `volume`, `snapshot`), CloudTrail event ID, and EventBridge event ID.
- Lambda enrichment fills `EC2 key name`, `instance type`, `volume size`, `volume type`, and `snapshot tier` by querying EC2 APIs when those fields are absent in raw CloudTrail payload.
- Some delete events may still have blanks if resource metadata is no longer retrievable at query time.
- Enriched messages are published to SNS as Amazon Q custom notification schema.

### Step 3) AWS Config Recording (`config`)

Command:

```bash
python3 setup_ec2_ebs_ami_audit.py config \
  --base-region us-east-1
```

Key arguments:

- `--config-bucket` (default `my-<account-id>-config-history`): optional override for Config S3 bucket.
- `--config-role-name` (default `AWSConfigRecorderRole`): IAM role name for Config recorder.
- `--config-recorder-name`: recorder name (default `default`).
- `--config-delivery-channel-name`: delivery channel name (default `default`).
- `--target-regions` (default auto): optional explicit region list.

What this step does:

- Creates/reuses Config S3 bucket and applies bucket policy.
- Creates/reuses Config IAM role and attaches `AWS_ConfigRole`.
- Creates/updates recorder and delivery channel in each target region.
- Starts recorder.

Existing vs missing behavior:

- Config S3 bucket:
  - Missing: created.
  - Existing and accessible: reused.
  - Existing but not creatable/reusable in your account: command fails.
- Config bucket policy: always applied via `put-bucket-policy` (overwrites current bucket policy document with the script policy).
- Config IAM role:
  - Missing: created with `config.amazonaws.com` trust policy.
  - Existing: reused.
- Config role policy attachment (`AWS_ConfigRole`): attach is re-run (idempotent for normal use).
- Recorder (`put-configuration-recorder`) and delivery channel (`put-delivery-channel`): create or update in place.
- Recorder start: always run via `start-configuration-recorder`.

What this step does not do:

- Does not send Slack messages.
- Does not backfill historical changes before recording was active.

Effects:

- Delivery channel `default` writes files to `s3://my-787744166714-config-history`.
- Writes incremental config history batches: `.../Config/<region>/YYYY/M/D/ConfigHistory/*.json.gz`
- Writes full point-in-time inventories: `.../Config/<region>/YYYY/M/D/ConfigSnapshot/*.json.gz`
- `ConfigSnapshot` is not just a copied history file; snapshot is full state at a timestamp, history is change deltas.
- In this account, `my-787744166714-config-history` was created on 2026-03-18 and the files currently under this bucket are from current AWS Config delivery activity.
- AWS Config itself may still have older history from prior periods/destinations (for example, a previous bucket), but that older data is not currently in this bucket.

### Step 4) Slack Binding (`slack`)

Command:

```bash
python3 setup_ec2_ebs_ami_audit.py slack \
  --alert-destination slack \
  --chatbot-region us-west-2 \
  --slack-channel-configuration-name test-configuration \
  --slack-team-id T09CK3AAC \
  --slack-channel-id C0AMDBXTDHC
```

Key arguments:

- `--chatbot-region` (default `--base-region`): region where Amazon Q/Chatbot API endpoint is used.
- `--slack-channel-configuration-name` (default `test-configuration`): config name.
- `--slack-team-id`, `--slack-channel-id` (defaults `T09CK3AAC`, `C0AMDBXTDHC`): Slack workspace/channel IDs.
- `--sns-topic-arns` (default empty): optional explicit topic ARNs; otherwise script resolves/creates regional topics named by `--event-topic-name`.
- `--chatbot-role-name` or `--chatbot-role-arn`: IAM role for Amazon Q.

What this step does:

- Creates/reuses IAM role for Amazon Q (`q.amazonaws.com` trust).
- Creates/updates Slack channel configuration.
- Links SNS topics to that Slack channel configuration.
- It only binds delivery; enrichment/formatting is handled in Step 2 Lambda when using Slack mode.

Existing vs missing behavior:

- Chatbot IAM role:
  - `--chatbot-role-arn` set: script uses that ARN directly and does not create role.
  - ARN not set and role missing: role is created.
  - ARN not set and role exists: role is reused.
- Chatbot role policy attachment (`--chatbot-role-policy-arn`): attach is re-run when provided.
- Slack channel configuration:
  - Missing configuration name: `create-slack-channel-configuration`.
  - Existing configuration name: `update-slack-channel-configuration`.
- For existing configuration names, the script updates that configuration and keeps its current Slack channel ID.
- SNS topic links on Slack update: merged as union of existing + new topic ARNs (deduplicated), not replaced by only-new unless explicitly narrowed outside this script.

What this step does not do:

- Does not create EventBridge rules.
- Does not itself generate events; it only binds delivery path.

Effects:

- SNS topics get Chatbot/Amazon Q subscription endpoints.
- Future matching EventBridge->SNS notifications appear in Slack channel.
- No S3 files are created by this step.

### Step 5) Full Setup (`all`)

Command (Slack path):

```bash
python3 setup_ec2_ebs_ami_audit.py all \
  --alert-destination slack \
  --slack-channel-configuration-name test-configuration \
  --slack-team-id T09CK3AAC \
  --slack-channel-id C0AMDBXTDHC \
  --chatbot-region us-west-2
```

Command (email path):

```bash
python3 setup_ec2_ebs_ami_audit.py all \
  --alert-destination email \
  --email-endpoint you@example.com
```

What this step does:

- Runs in sequence: `cloudtrail` -> `events` -> `slack` (if destination is slack) -> `config`.
- Reuses existing resources where possible and updates in place.

Existing vs missing behavior summary:

- Most resources are handled as create-or-update/reuse (idempotent style).
- Some settings are intentional overwrite/update on each run (S3 bucket policies, SNS topic policy, EventBridge rule/target definitions).
- Some conflict states still fail fast (for example, inaccessible or conflicting bucket ownership, invalid IAM/Slack identifiers, missing required email endpoint for email mode).

Show all options:

```bash
python3 setup_ec2_ebs_ami_audit.py --help
```

Legacy shell script still exists as `setup_ec2_ebs_ami_audit.sh`.

Detailed run/verify playbook:

- [AWS Audit Setup Runbook](docs/audit_setup_runbook.md)
