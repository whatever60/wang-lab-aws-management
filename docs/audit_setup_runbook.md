# AWS Audit Setup Runbook (Step-by-Step)

This runbook records the EC2/EBS/AMI audit baseline rollout using:

`python3 setup_ec2_ebs_ami_audit.py`

Account used in this rollout: `787744166714`

## AWS CLI Version Baseline

Use AWS CLI v2 for this runbook (required for `aws chatbot` commands).

Upgrade command used in this environment:

```bash
mkdir -p /tmp/awscliv2-install
cd /tmp/awscliv2-install
curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o awscliv2.zip
unzip -q -o awscliv2.zip
./aws/install --install-dir "$HOME/.local/aws-cli" --bin-dir "$HOME/.local/bin" --update
aws --version
```

Observed version after upgrade:

- `aws-cli/2.34.12`

## Defaults Used

- Base region: `us-east-1`
- Trail name: `account-audit-trail`
- EventBridge rule name: `ec2-ebs-ami-audit`
- SNS topic name: `asset-audit-events`
- Lambda enricher function name: `ec2-ebs-ami-audit-enricher`
- Lambda enricher role name: `EC2EBSAMIAuditEnricherRole`
- Config recorder name: `default`
- Config delivery channel name: `default`
- CloudTrail bucket: `my-787744166714-cloudtrail-audit`
- AWS Config bucket: `my-787744166714-config-history`

## Step 1: CloudTrail Baseline

### Command Run

```bash
python3 setup_ec2_ebs_ami_audit.py cloudtrail \
  --base-region us-east-1 \
  --trail-name account-audit-trail
```

### Resources Created or Updated

- S3 bucket: `my-787744166714-cloudtrail-audit` (created if missing)
- S3 bucket policy for CloudTrail delivery (updated)
- CloudTrail trail: `account-audit-trail` (created or updated)
- CloudTrail logging state (started)

### Success Verification

Run:

```bash
aws cloudtrail get-trail-status \
  --name account-audit-trail \
  --region us-east-1 \
  --output json
```

Success signals:

- `IsLogging` is `true`
- `TimeLoggingStarted` is populated

Observed in this rollout:

- `IsLogging: true`
- `TimeLoggingStarted: 2026-03-18T19:38:38Z`

## Step 2: EventBridge + SNS (Alert Pipeline)

### Command Run

Slack destination mode (no email subscription creation):

```bash
python3 setup_ec2_ebs_ami_audit.py events \
  --base-region us-east-1 \
  --alert-destination slack
```

### Resources Created or Updated

Per enabled region:

- SNS topic: `asset-audit-events` (created if missing)
- EventBridge rule: `ec2-ebs-ami-audit` (put-rule)
- In email mode:
  - SNS topic policy allowing EventBridge publish (updated)
  - EventBridge target `sns1` -> regional SNS topic ARN
- In Slack mode:
  - IAM role `EC2EBSAMIAuditEnricherRole` for Lambda (create/update)
  - Lambda function `ec2-ebs-ami-audit-enricher` in each target region (create/update)
  - EventBridge target `enricher1` -> regional Lambda ARN
  - Lambda publishes enriched Amazon Q custom notification JSON to SNS

### Success Verification

Example checks in `us-east-1`:

```bash
aws events describe-rule \
  --name ec2-ebs-ami-audit \
  --region us-east-1 \
  --output json

aws events list-targets-by-rule \
  --rule ec2-ebs-ami-audit \
  --region us-east-1 \
  --output json

aws lambda get-function \
  --function-name ec2-ebs-ami-audit-enricher \
  --region us-east-1 \
  --output json

aws sns get-topic-attributes \
  --topic-arn arn:aws:sns:us-east-1:787744166714:asset-audit-events \
  --region us-east-1 \
  --output json
```

Success signals:

- Rule `State` is `ENABLED`
- Email mode: target ARN points to SNS topic and SNS policy allows `events.amazonaws.com` to publish
- Slack mode: target ARN points to Lambda function, Lambda exists, and Lambda environment has `TOPIC_ARN` set

## Step 3: AWS Config (EC2 + EBS History)

### Command Run

```bash
python3 setup_ec2_ebs_ami_audit.py config \
  --base-region us-east-1
```

### Resources Created or Updated

- S3 bucket: `my-787744166714-config-history` (created if missing)
- S3 bucket policy for Config delivery (updated)
- IAM role: `AWSConfigRecorderRole` (created if missing)
- Policy attached: `arn:aws:iam::aws:policy/service-role/AWS_ConfigRole`
- Per enabled region:
  - Configuration recorder `default` (EC2 instance + EBS volume resource types)
  - Delivery channel `default` (to Config S3 bucket)
  - Recorder started

### Success Verification

Example checks in `us-east-1`:

```bash
aws configservice describe-configuration-recorders \
  --region us-east-1 \
  --output json

aws configservice describe-configuration-recorder-status \
  --region us-east-1 \
  --output json

aws configservice describe-delivery-channels \
  --region us-east-1 \
  --output json
```

Success signals:

- Recorder exists with `name: default`
- Recorder status has `recording: true` and `lastStatus: SUCCESS`
- Delivery channel exists and points to `my-787744166714-config-history`

Observed in this rollout:

- `us-east-1` recorder `recording: true`, `lastStatus: SUCCESS`
- `us-west-2` recorder `recording: true`, `lastStatus: SUCCESS`

## Step 4 (Optional): Link SNS to Slack (Amazon Q Developer in chat applications)

Run when AWS CLI supports `chatbot` commands (AWS CLI v2 recommended).

### Command

```bash
python3 setup_ec2_ebs_ami_audit.py slack \
  --alert-destination slack \
  --base-region us-east-1 \
  --chatbot-region us-west-2 \
  --slack-channel-configuration-name test-configuration \
  --slack-team-id T09CK3AAC \
  --slack-channel-id C0AMDBXTDHC
```

Observed in this environment:

- `chatbot` endpoint in `us-east-1` was unreachable.
- `us-west-2` worked and was used for channel configuration.

### Resources Created or Updated

- IAM role `ChatbotSlackRole` (if missing) with trust for `q.amazonaws.com`
- Managed policy attachment for the role (default: `CloudWatchReadOnlyAccess`)
- Slack channel configuration `test-configuration` (create or update)
- SNS topic ARNs linked into Slack configuration

### Verification

```bash
aws chatbot describe-slack-channel-configurations \
  --region us-west-2 \
  --output json
```

Success signal:

- Config entry exists for `ConfigurationName: test-configuration`
- `SnsTopicArns` includes your `asset-audit-events` topic ARNs

## Idempotency Behavior (Existing Resources)

Current script behavior:

- S3 buckets: create-if-missing, reuse-if-exists
- CloudTrail trail: update-if-exists, create-if-missing
- SNS topic: create API is idempotent; existing topic is reused
- EventBridge rule/targets: `put-rule` and `put-targets` update in place
- Lambda enricher role/function: create-if-missing, update-if-exists
- IAM roles: create-if-missing, reuse-if-exists
- AWS Config recorder and delivery channel: `put-*` updates in place
- Slack channel configuration: create-if-missing, update-if-exists
