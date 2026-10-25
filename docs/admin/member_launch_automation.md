# Background EC2 Ownership and Personal S3 Access

Members launch through the standard AWS console, CLI or SDK. One existing
`wanglab-member-access-sync` Lambda handles membership/role lifecycle and native
EC2 creation. One EventBridge rule handles IAM changes, successful EC2 creation
events and a five-minute repair schedule. There is no per-member launch broker,
extra console, queue, database or required template workflow.

## Authoritative Identity

`lab_members`, live IAM `AccessRole=CurrentMember` / `HomeBucket` tags, and
account-local S3 home ownership define who receives a personal role. The home
bucket must have `BucketScope=User`, `BucketOwner=<IAM username>` and
`OwnerAccessRole=CurrentMember`. The controller rechecks live identity and home
ownership before grants; offboarding revocations run before new grants.

Roles and profiles remain under `/wanglab/member-s3/`, named after the exact
IAM username, and carry protected `ManagedBy` / `Component` / ownership markers.
Role policies and the managed S3 boundary restrict approved lab reads and
personal home writes. The role has no EC2 management or IAM authority.

## Native Creation

The controller reads successful CloudTrail `RunInstances`, `CreateVolume`,
`CreateKeyPair`, `ImportKeyPair`, `CreateSecurityGroup`, `CreateSnapshot` and
`CreateImage` records, plus native network, address, template and image/snapshot
copy creation. The deployment's `native_since` timestamp separates new
resources from historical infrastructure. Replays require matching account,
region, IAM username and immutable IAM UserId. Names, keys and caller-provided
Owner tags never establish creator authority.

It attributes newly created resources with `wanglab:Owner` and
`wanglab:CreatorUserId`. Only the created target's ID is adopted; a new subnet
does not confer ownership of its source VPC. RunInstances attribution includes
newly created attached disks and interfaces, while excluding older disks and
explicitly supplied existing interfaces. Existing ownership is not reassigned.
Member policies prevent writing the provenance markers used for role attachment.

After attributing an instance, the controller attaches the verified creator's
personal profile only when all of these hold: it is a post-cutover instance,
its protected `wanglab:CreatorUserId` matches the current IAM identity,
membership/home ownership are valid, the managed profile contains the exact personal role, and
there is no existing/associating instance profile. It never replaces or removes
an existing profile, starts/stops a machine or reads S3 objects.

The repair schedule replays the last 24 hours of creation records. Event-driven
runs limit the lookup to that event type; actual audit records remain the
authority. Protected
resource provenance persists on the instance, allowing a delayed blank-profile
repair after the event leaves the replay window. Native creation is not gated
on reconciliation. Owner-based restrictions and S3 credentials are asynchronous;
this shared account does not provide instantaneous tenant isolation or a
first-boot S3 readiness guarantee.

## Minimal Runtime Configuration

Keep live values in ignored `config/member_access.local.json`:

```json
{
  "ec2_config": {
    "account_id": "111122223333",
    "regions": ["us-east-1"]
  },
  "permissions_boundary_arn": "arn:aws:iam::111122223333:policy/WangLabMemberS3Boundary",
  "native_since": "2026-10-25T00:00:00Z"
}
```

No AMI/type/subnet/SG registry, flavor list or IAM template-pointer tags are
required. The old optional template configuration remains readable for
compatibility, but native deployments do not provision or maintain templates.

## Offboarding and Failure Handling

Removing a member, invalidating home ownership or losing required identity
metadata revokes the managed personal role. The controller removes legacy
pointers where relevant, sets role state to an explicit Deny-all and denies new
role assumptions. Existing issued role credentials lose authority after IAM
propagation. EC2 instances/data and Linux/SSH access are preserved and need
separate lifecycle decisions.

Reserved concurrency one serializes automatic and administrative sync. Native
Lambda retries, CloudWatch logs and the existing error alarm surface failures.
The schedule repairs missed events. Slack audit notifications remain independent
and are not enabled by this controller. Failed reconciliation is not success.

```bash
aws-audit member-access plan --config config/member_access.local.json
aws-audit member-access sync
aws-audit member-access package --source-root src --output outputs/member-access.zip
aws-audit member-access render-stack --config config/member_access.local.json \
  --artifact-bucket YOUR_PRIVATE_ARTIFACT_BUCKET \
  --artifact-key member-access/releases/REVIEWED_RELEASE.zip
```

The package uses a fixed source-only allowlist. It includes no local config,
credentials, rosters, data or partial SDK dependencies; Lambda supplies Boto3.

[AWS event-based attribution](https://aws.amazon.com/blogs/security/how-to-automatically-tag-amazon-ec2-resources-in-response-to-api-events/),
[AWS post-launch profile association](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/attach-iam-role.html)
