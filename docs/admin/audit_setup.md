# Quiet Audit Recording

The audit setup command maintains one multi-Region CloudTrail archive and AWS
Config recording in `us-east-1`. CloudTrail supplies API history across regions;
Config supplies resource state history used for cost attribution. Routine Slack
audit notifications and their dedicated EventBridge rule, enrichment Lambda,
DynamoDB table, SNS topic and IAM role are retired. The setup command cannot
recreate that pipeline. Existing CPU auto-stop alarms and their tagging/alert
infrastructure are independent and remain in place.

## Region Scope

Workloads and automation use `us-east-1`. Config setup defaults to that base
region without discovering or provisioning other regions. `--target-regions`
accepts an explicit list or `all` for an administrator's deliberate deployment;
`TARGET_REGIONS` has the same behavior. One multi-Region CloudTrail remains
managed from the base region and delivers into one S3 bucket. Config region
selection does not narrow CloudTrail coverage.
[AWS multi-Region trails](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-multi-region-trails.html)

Preserve historical CloudTrail and Config delivery objects when retiring regional
recorders. Monthly cost reports may query historical regions with earlier charges.
A stopped Config recorder has no new resource-state history there; CloudTrail
API records do not replace that timeline. The existing historical S3 bucket
outside the primary region keeps its existing data access.

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

Run from an authenticated administrator environment. Local bucket names belong
in ignored configuration or environment variables.

```bash
uv run aws-audit audit-setup --help
uv run aws-audit audit-setup cloudtrail \
  --base-region us-east-1 \
  --trail-name account-audit-trail \
  --trail-bucket "$CLOUDTRAIL_BUCKET"
uv run aws-audit audit-setup config \
  --base-region us-east-1 \
  --config-bucket "$CONFIG_BUCKET"
```

The default `all` command combines CloudTrail with Config in the base region;
it does not select all regions. Setup is create-or-update and must be reviewed
before execution because it reconciles recorder and delivery bucket settings.
The historical `setup_ec2_ebs_ami_audit.sh` entry point forwards to this same
Python implementation and accepts its current flags. It uses `python3`, or
`AWS_AUDIT_PYTHON` if set, and works from another directory.

Check the recording baseline without publishing notifications:

```bash
aws cloudtrail get-trail-status --name account-audit-trail --region us-east-1
aws configservice describe-configuration-recorder-status --region us-east-1
```
