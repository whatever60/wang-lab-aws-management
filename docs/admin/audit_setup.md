# Audit Alert Setup

The audit setup command provisions the optional account-level audit baseline:

- CloudTrail trail and delivery bucket
- EventBridge rules for EC2/EBS/AMI events
- SNS topics
- optional Lambda enrichment for Slack/Amazon Q notifications
- AWS Config recorder and delivery channel

Use this only from an authenticated AWS CLI environment for the target account.

## Default: Record Without Routine Notifications

Keep workloads, automation, and AWS Config in `us-east-1`. By default, regional
setup targets only `--base-region` (`us-east-1`), including Config's EC2/volume
history used for cost attribution. No account-wide region discovery happens
unless `--target-regions all` is explicitly selected. To target a different
set, pass a comma- or space-separated region list with `--target-regions`.
`TARGET_REGIONS` supports the same explicit selections; leave it unset for the
single-region default.

CloudTrail remains one multi-Region trail managed from the base region,
delivering account activity to one S3 bucket. `--target-regions` does not narrow
its coverage. Cross-region API activity therefore remains available for later
investigation without regional notification processors.
[AWS multi-Region trail behavior](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-multi-region-trails.html)

Routine notifications are opt-in; the default `--alert-destination none`
disables existing matching notification rules without creating SNS topics,
enricher functions or thread-state tables. CloudTrail and Config remain
independent. To pause matching notification rules across all enabled regions,
including a previous multi-region deployment, explicitly select `all`:

```bash
uv run aws-audit audit-setup events --alert-destination none --target-regions all
```

This pause command retains existing notification resources. A single-region
consolidation can then remove the unused regional rules, targets, enrichment
functions, state tables, audit SNS topics, and dedicated logs after saving
their configuration. The setup command does not delete resources outside its
selected regions or stop old Config recorders automatically.

For an immediate Slack mute, detach the audit SNS topics from the Amazon Q
channel configuration as well; preserve unrelated topic bindings. No test
message is needed. AWS supports the optional Q chat API in selected regions;
the CLI defaults to its `us-east-2` endpoint, independently of workload region.
[AWS chat API regions](https://docs.aws.amazon.com/chatbot/latest/APIReference/Welcome.html)

Routine Slack notifications are disabled for the current architecture. There
is no central notification pipeline to maintain. Use the explicit notification
options below only if a concrete need returns.

## Consolidating an Older Multi-region Deployment

Before retiring regional compute, preserve its disks and recovery metadata in
the primary region and verify the copies. Preserve existing CloudTrail and
Config objects in the delivery buckets; they contain historical evidence and
are not notification state. Once out-of-region resources are retired, stop
their Config recorders and remove their unused delivery channels and recorder
definitions. Keep the `us-east-1` recorder and shared delivery infrastructure.

The monthly compute report still discovers regions with charges from Cost
Explorer and can query their historical Config records. Retiring a recorder
stops new state history in that region. Existing delivery objects and retained
service history do not recreate missing future state, so later out-of-region
compute can have incomplete runtime or ownership attribution. CloudTrail
continues to capture API activity, but does not replace Config's state timeline.
Historical reports may still mention retired regions because their earlier
usage remains billable history.

## Primary-region IAM Guardrail

`config/primary_region_guardrail.json` is a static, deny-only identity policy.
Deploy one customer-managed copy and attach it to the existing `admin` and
`lab_members` groups. It grants no access and leaves all existing allow policies
and member resource restrictions in place. It follows AWS's
[requested-region deny pattern](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_aws_deny-requested-region.html).

Regional API calls outside `us-east-1` are denied, with explicit exceptions for
the listed global/account services, billing interfaces, STS, S3 and Amazon Q
chat configuration. Cross-region EC2 Describe, Config Describe/Get/List and
CloudTrail Describe/Get/List/LookupEvents remain available when existing
policies permit them. EC2 DeleteSnapshot, DeleteVolume, DeregisterImage,
TerminateInstances and StopInstances are also excepted so administrators can
retire historical resources without temporarily bypassing the guardrail.
This does not grant members additional rights or exempt EC2 creation, Start
or Modify operations. Existing KMS Decrypt, GenerateDataKey and DescribeKey
permissions are preserved for encrypted-data dependencies; out-of-region key
creation and policy changes remain denied.

Legacy S3 data outside the primary region is retained pending a separate
migration decision. Existing S3 read/write permissions continue to work in
those regions. A separate deny prevents new general-purpose buckets outside
`us-east-1` using `s3:LocationConstraint`. The presence check preserves normal
`us-east-1` requests, which omit that value.
[S3 CreateBucket behavior](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html)

This is a daily-use IAM guardrail, not an SCP or account-wide isolation. An
administrator can detach it; root and role sessions do not inherit IAM group
policies. Service roles are unchanged. `aws:RequestedRegion` controls the API
endpoint, not every cross-region side effect; exempted services and permitted
role assumption can still have effects elsewhere.
[AWS condition-key limitations](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-requestedregion)

Before attaching it, use IAM simulation to check out-of-region create/update
denials, primary-region operations, the historical read and listed EC2 cleanup
exceptions, billing and chat endpoints, existing S3/KMS access, and bucket
creation with omitted, primary-region and other-region location values.
Validate it alongside the
actual user policies; a deny-only document cannot show whether another policy
grants the underlying access. Remove the policy attachment to roll back.

## Commands

Show available setup commands:

```bash
uv run aws-audit audit-setup --help
```

Create or update CloudTrail:

```bash
uv run aws-audit audit-setup cloudtrail \
  --base-region us-east-1 \
  --trail-name account-audit-trail \
  --trail-bucket "$CLOUDTRAIL_BUCKET"
```

Create or update Config only in `us-east-1`:

```bash
uv run aws-audit audit-setup config \
  --base-region us-east-1 \
  --config-bucket "$CONFIG_BUCKET"
```

The default `all` command combines this single-region Config setup with the
multi-Region CloudTrail and the disabled-notification setting. Selecting the
`all` command does not select all regions.

Create or update EventBridge and SNS in email mode:

```bash
uv run aws-audit audit-setup events \
  --base-region us-east-1 \
  --alert-destination email \
  --email-endpoint "$ALERT_EMAIL"
```

Create or update EventBridge, Lambda enrichment, and Slack routing:

```bash
uv run aws-audit audit-setup all \
  --base-region us-east-1 \
  --alert-destination slack \
  --slack-channel-configuration-name "$SLACK_CONFIG_NAME" \
  --slack-team-id "$SLACK_TEAM_ID" \
  --slack-channel-id "$SLACK_CHANNEL_ID" \
  --config-bucket "$CONFIG_BUCKET" \
  --trail-bucket "$CLOUDTRAIL_BUCKET"
```

## Local Values

Do not commit account-specific values. Keep these in a local shell profile,
`.env`, secret manager, or deployment notes outside the repo:

- AWS account ID
- delivery bucket names
- Slack workspace and channel IDs
- notification email addresses
- custom IAM role names if they are site-specific

The command intentionally fails early when Slack setup is requested without Slack IDs.

The old `setup_ec2_ebs_ami_audit.sh` entry point forwards to this same Python
command. Its flags and environment defaults (for example `BASE_REGION`,
`ALERT_DESTINATION`, `SLACK_TEAM_ID` and `SLACK_CHANNEL_ID`) remain supported;
explicit flags override environment values. There is one deployment implementation.
The wrapper uses `python3` directly, or `AWS_AUDIT_PYTHON` if set, and works from
another directory without requiring a separate package installation.
The default enricher ZIP is built from the packaged Python source, independent
of the working directory.

## Validation

After setup, validate with AWS CLI read-only calls:

```bash
aws cloudtrail get-trail-status \
  --name account-audit-trail \
  --region us-east-1

aws events describe-rule \
  --name ec2-ebs-ami-audit \
  --region us-east-1

aws configservice describe-configuration-recorder-status \
  --region us-east-1
```

The setup command is intended to be rerunnable. Some resources are create-or-update;
bucket policies and EventBridge targets are reconciled to the desired shape.
