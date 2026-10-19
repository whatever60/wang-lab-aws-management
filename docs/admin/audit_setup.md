# Audit Alert Setup

The audit setup command provisions the optional account-level audit baseline:

- CloudTrail trail and delivery bucket
- EventBridge rules for EC2/EBS/AMI events
- SNS topics
- optional Lambda enrichment for Slack/Amazon Q notifications
- AWS Config recorder and delivery channel

Use this only from an authenticated AWS CLI environment for the target account.

## Default: Record Without Routine Notifications

Use `us-east-1` as the primary workload and audit-management region while
retaining multi-Region CloudTrail delivery to one S3 bucket. Regional Config
recorders supply EC2/volume history for cost attribution. A home region does
not restrict a multi-Region trail's coverage.
[AWS multi-Region trail behavior](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-multi-region-trails.html)

Routine notifications are opt-in; the default `--alert-destination none`
disables existing matching notification rules without creating SNS topics,
enricher functions or thread-state tables. CloudTrail and Config remain
independent. To pause across all enabled regions:

```bash
uv run aws-audit audit-setup events --alert-destination none
```

Rules and notification resources are retained for a reversible pause. For an
immediate Slack mute, detach the audit SNS topics from the Amazon Q channel
configuration as well; preserve unrelated topic bindings. No test message is
needed. AWS supports the Q chat API in selected regions; the CLI defaults to
its `us-east-2` endpoint, independently of workload region.
[AWS chat API regions](https://docs.aws.amazon.com/chatbot/latest/APIReference/Welcome.html)

If real-time notifications become useful again, prefer one central processor
with regional event forwarding and only actionable alerts. Until then, do not
build a replacement processing pipeline solely to centralize an unused feature.

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
