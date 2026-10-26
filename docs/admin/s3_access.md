# S3 Access Reconciliation

The S3 access reconciler manages IAM tags, bucket tags, IAM policies, group policy
attachments, and bucket guardrails from a manifest.

## Local Manifest

The committed file is a redacted example:

```text
config/s3_access_manifest.example.json
```

Copy it to the ignored local path and fill in real account data:

```bash
cp config/s3_access_manifest.example.json config/s3_access_manifest.local.json
```

Do not commit the local manifest.

The manifest must contain **every IAM user and S3 bucket in the account**. The
reconciler checks this inventory and exact membership of all three role groups;
it does not create users, buckets, or group memberships. During onboarding, create
the resources and update the full local manifest before planning reconciliation.
Do not infer an untagged bucket's scope or owner just to make validation pass.

Before contacting AWS, validation rejects duplicate user/bucket names, unknown
roles or scopes, missing/reused role groups, and inconsistent home ownership.
Each `User` bucket must name an existing owner whose `home_bucket` points back
to that bucket; a user's home must be a `User` bucket owned by that same user.
Users without a home bucket are supported.

## Plan And Apply

Plan:

```bash
uv run aws-audit s3-access plan
```

Apply:

```bash
uv run aws-audit s3-access apply
```

When the member-access controller is deployed, synchronize personal instance
roles immediately after a successful apply:

```bash
uv run aws-audit s3-access apply --sync-member-access
```

This invokes the serialized deployed reconciler after S3 reconciliation succeeds.
It requires permission to invoke that Lambda and is rejected with `plan`.
The controller also watches IAM membership/tag changes and runs every five
minutes; it derives current membership and home ownership from live metadata.
Its deployed environment contains approved infrastructure rather than a user roster.
See [member launch automation](member_launch_automation.md) for the role boundary,
already-issued-session revocation and operational checks.

Use `--manifest` to point at another local manifest:

```bash
uv run aws-audit s3-access plan --manifest path/to/manifest.local.json
```

## Model

New S3 buckets are provisioned by administrators. Ordinary members cannot
create buckets, including in `us-east-1`; this is an explicit exception to
normal self-service resource creation. The existing member/admin own-home
write policy denies general-purpose, directory, table and vector bucket
creation unless the trusted `AccessRole` principal tag is `Admin`. Missing
tags do not bypass the deny. Administrator bucket creation still follows
the primary-region guardrail and the existing manifest/ownership workflow.

Users have an `AccessRole` and optionally a `HomeBucket`. Buckets have a `BucketScope`
and optionally a `BucketOwner`.

Typical scopes:

- `User`: a user's own bucket.
- `SharedOps`: shared operational data, writable by admins only.
- `ServiceManaged`: service or application buckets with their existing
  access policies; administrators receive reads, while member-wide reads and the
  `SharedOps` admin-write guardrail are not added.

Choose by the bucket's actual use and access policy, not by whether its name
contains a person's name. An application bucket already used by an instance role
can use `ServiceManaged` without creating another role or changing that bucket
policy. The reconciler preserves service-managed policies.

The reconciler is intentionally explicit: ambiguous users or buckets should be fixed in
the manifest instead of guessed.

## Alumni EC2 Guardrail

Alumni retain only the eleven explicitly listed EC2 Describe permissions in
`ALUMNI_EC2_DESCRIBE_ACTIONS`, in addition to their approved S3 reads. The direct
EC2 deny uses `NotAction` with that same allowlist, `Resource="*"`, and both:

- `Bool: {"aws:ViaAWSService": "false"}` to preserve the direct-request boundary.
- `Null: {"ec2:Region": "false"}` to require the EC2 service context.

AWS documents that every EC2 action supports `ec2:Region`. Requiring its presence
keeps the `NotAction` deny from matching unrelated S3 or IAM requests. The wildcard
resource also covers EC2 operations that do not support resource-level permissions.
Other direct EC2 operations remain explicitly denied even if another identity
policy grants `ec2:*`; no extra services or S3 actions are allowed by this change.

See the [EC2 IAM condition-key documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-policies-for-amazon-ec2.html)
and [IAM NotAction semantics](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html).

For a targeted repair, `alumni_ec2_statements()` builds the two EC2 statements
without AWS calls. Replace the existing `DenyDirectEc2Mutation` statement in the
live alumni policy, and compare every other statement before creating a new
version. A full reconciliation additionally affects the manifest's other policies,
tags, and bucket guardrails.

`HpcUid` is managed separately in IAM. S3 reconciliation preserves it, including
when a member's role changes. Retain historical UID allocations during offboarding
and never assign them to another person.
