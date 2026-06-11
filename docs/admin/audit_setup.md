# Audit Alert Setup

The audit setup command provisions the optional account-level audit baseline:

- CloudTrail trail and delivery bucket
- EventBridge rules for EC2/EBS/AMI events
- SNS topics
- optional Lambda enrichment for Slack/Amazon Q notifications
- AWS Config recorder and delivery channel

Use this only from an authenticated AWS CLI environment for the target account.

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
