# Personal Launch-Template Automation

`aws_audit.member_access` provisions a personal S3 role, instance profile, and
four EC2 launch templates for each eligible current member. The native console
flow is documented in [Launch a Personal EC2 Instance](../user/ec2_launch.md).
The [member EC2 policy](ec2_member_access.md) permits only the member's published
templates and exact personal profile. Onboarding does not require a new global
group-policy version for every user.

## Identity and Managed Resources

The live IAM group **`lab_members`** is authoritative. The controller also reads
the user's live `AccessRole=CurrentMember` and `HomeBucket` tags. It checks the
home bucket with `GetBucketTagging` and `ExpectedBucketOwner` equal to the
configured account; the live bucket tags must be `BucketScope=User`,
`BucketOwner=<exact IAM username>`, and `OwnerAccessRole=CurrentMember`.
Membership or ownership is never inferred from display names or key names.

| Resource | Naming and binding |
| --- | --- |
| IAM role | Path `/wanglab/member-s3/`, name exactly the IAM username |
| Instance profile | Same path and name; contains only that personal role |
| Launch templates | `wanglab-member-<username>-Ubuntu2404`, `-Al2023`, `-DL2204`, `-DL2404` |
| Managed-resource markers | `ManagedBy=wanglab-aws-management`, `Component=member-launch` |
| Role/profile ownership | `Owner`, `HomeBucket`, and `AccessRole` tags |
| Template ownership | Same markers and ownership tags, plus exact `Flavor` |

Only roles, profiles, and templates bearing both management markers in the
expected namespace may be changed. A foreign name collision or a managed ownership/home mismatch
blocks that member and requires administrative review. The controller does not
silently adopt a foreign role/profile/template or reassign a home bucket.

Ordinary usernames retain the template naming shown above. If a username has
characters outside EC2's template-name alphabet, those characters become `-`
and a 12-hex-character SHA256 suffix of the original username is appended to
the username component. This prevents normalization collisions. Owner tags and
role/profile names retain the exact IAM username; authorization binds full
template ARNs rather than relying on template-name matching.
[AWS template-name constraints](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_LaunchTemplate.html)

For active members, these four protected **IAM user tags** contain full launch
template ARNs:

| Flavor | IAM user tag |
| --- | --- |
| `Ubuntu2404` | `MemberLaunchUbuntu2404` |
| `Al2023` | `MemberLaunchAl2023` |
| `DL2204` | `MemberLaunchDL2204` |
| `DL2404` | `MemberLaunchDL2404` |

All four are published only after the role, boundary, profile binding, and
template defaults are verified. The member policy requires all four pointers,
current-member identity tags, the exact personal profile, and template Owner.
Members cannot write these IAM tags or mutate template versions/defaults.

## S3 Role and Template Defaults

An active role trusts only `ec2.amazonaws.com`. It attaches the existing
`WangLabS3AccessReadApproved` and `WangLabS3AccessCurrentMemberWriteOwn` policies.
The managed inline policy `WangLabMemberRoleState` explicitly denies non-S3
services, except identity-only `sts:GetCallerIdentity`. Its narrow own-home
read/list Allow keeps a newly onboarded home usable before the shared approved
read policy's bucket list is refreshed. The mandatory
`WangLabMemberS3Boundary` caps the role to account-local S3 data/list operations
and own-home object writes; it is a ceiling, not an independent grant. Bucket
administration and non-S3 management remain outside that boundary.

Templates use reviewed AMI/type/subnet/SG sources, the personal profile, a new
public-IPv4 network interface with `DeleteOnTermination=true`, and
`MetadataOptions.HttpTokens=required`. Instance, volume, and network-interface
tag specifications each contain exact Owner, `Project=personal`, and optional
Name. The four starting flavors are Ubuntu 24.04 and Amazon Linux 2023 on
`t3.micro`, and NVIDIA Ubuntu 22.04/24.04 deep learning images on `g6.xlarge`.
Approved final-request overrides remain subject to the member policy.

EC2 key metadata must contain `Owner=<exact IAM username>`. Zero verified keys
means `pending_key`: the role stays inactive, templates may be prepared without
KeyName, and no four-pointer grant is published. Multiple verified owned keys
are allowed. A consistent, still-owned default already present in the templates
is preserved; otherwise the first key name in sorted order becomes the default.
Other owned keys remain selectable at launch. No private key is read, generated,
or transferred by this controller.

The reconciler never attaches or replaces a profile on an existing EC2
instance. Initial adoption changes credential setup only for new launches from
these templates. Later permission changes affect all instances already using a
managed personal role. Do not use personal profiles on shared HPC nodes:
processes with metadata access share the role's S3 authority.
[AWS EC2 instance-role model](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html)

## Reconciliation and Offboarding

The controller runs in the account's **`us-east-1`** region. EventBridge invokes
`wanglab-member-access-sync` for CloudTrail IAM events `AddUserToGroup`,
`RemoveUserFromGroup`, `TagUser`, `UntagUser`, and `DeleteUser`. A five-minute
scheduled rule repairs missed events, key changes, and bucket-tag changes.
CloudTrail management-event delivery must include the relevant IAM events in
this region. The deployed function has reserved concurrency one; manual sync
uses the same function so ordinary event/manual runs are serialized.

Each pass constructs identity input from live group/user/bucket metadata,
captures managed-resource metadata, and builds a deterministic plan. Apply
rechecks that the preview is unchanged. All known revocations are attempted
before any provisioning or activation. Grant checks repeat before and after
publishing access; membership churn causes retry or a grant-free pass.
Unchanged policies, templates, and user pointers produce no repeat writes.

For a removed/deleted member, invalid ownership, or unreadable per-member
identity metadata, the controller removes the four user pointers where the
user still exists and sets the managed role's state to **Deny `*` on `*`**. It
also denies EC2 role trust and marks the role inactive. The explicit role Deny
applies to already-issued sessions after IAM propagation; changing trust alone
would address only new assumptions. Roles, profiles, templates, instances, and
data are preserved. IAM group removal does **not** revoke Linux/SSH access or
stop compute; those offboarding actions need their own approved workflow.
[AWS role-session denial](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html)

An unreadable member home/user blocks that member rather than allowing stale
identity metadata to grant access. Other known offboarding still proceeds.
Unverified role-resource ownership is not permission to mutate it; the run
returns a retryable failure and does not grant past an unfinished revocation.
Global group/managed-resource-discovery failures abort without interpreting
the failure as an empty roster. Role existence is retained if its inline state
policy disappears between metadata calls, so that missing guard cannot hide an
offboarding target.

Event delivery is best effort. The five-minute schedule is a repair interval,
not a hard revocation deadline. Lambda retries, failures, and IAM propagation
can extend the interval. Check the function's error alarm, CloudWatch logs, and
failure queue; SDK diagnostics contain only sanitized operation/error codes,
not full event bodies, credentials, or plans.
[AWS IAM propagation behavior](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot.html#troubleshoot_general_eventual-consistency)

## Configuration and Administrative Commands

Keep live inventory in ignored, private configuration such as
`config/member_access.local.json`. The deployed SSM String parameter
`/wanglab/member-access/config` contains approved infrastructure, not a static
member roster or credentials:

- `ec2_config`: the reviewed member EC2 policy configuration, including
  `member_launch` with the protected paths/four tag keys and
  `require_template=true`.
- `flavors`: exactly four objects with `name`, `region`, `image_id`,
  `instance_type`, `subnet_id`, and `security_group_id`; all sources must be
  approved by `ec2_config`.
- `member_group`: `lab_members`.
- `permissions_boundary_arn`: the stack-managed
  `arn:aws:iam::111122223333:policy/WangLabMemberS3Boundary` for the actual account.

Use administrator credentials for these commands. Live `plan` and `sync`
require boto3 in the administrative Python environment. The installed
`aws-audit` entry point and `python -m aws_audit.cli` expose the same command groups.

Preview **live metadata** without applying changes:

```bash
umask 077
aws-audit member-access plan --config config/member_access.local.json > outputs/member-access-plan.json
```

Review desired templates, role/profile ARNs, pending-key members, blocked
identities/collisions, and ordered operations. The preview does not read S3
objects. It contains private account inventory; do not commit it.

Invoke the deployed serialized reconciler, using its default function name:

```bash
aws-audit member-access sync
```

S3 onboarding/offboarding can force the same sync after its own successful
apply, avoiding reliance on the next event or timer:

```bash
aws-audit s3-access apply --manifest config/s3_access_manifest.local.json --sync-member-access
```

The hook is valid only with `apply`. A failed synchronization is not a
successful onboarding/offboarding completion; inspect the function failure
and retry after correction.

Build the source-only Lambda ZIP **offline**:

```bash
aws-audit member-access package --source-root src --output outputs/member-access.zip
```

The fixed package allowlist excludes local configuration, credentials, outputs,
and data. Render a reviewable CloudFormation template **offline**, replacing
the artifact placeholders with an already-uploaded approved release:

```bash
aws-audit member-access render-stack --config config/member_access.local.json \
  --artifact-bucket YOUR_PRIVATE_ARTIFACT_BUCKET \
  --artifact-key member-access/releases/REVIEWED_RELEASE.zip \
  > outputs/member-access-stack.json
```

Rendering and packaging do not upload or deploy anything. Artifact upload,
CloudFormation deployment with named-IAM capability, and code/config changes
are separate administrator operations. The stack defines the data boundary,
SSM parameter, serialized Lambda/controller role, IAM-event and periodic rules,
error alarm, and encrypted failure queue. Keep the artifact private and tie
releases to reviewed source and package checksums.

## Trust and Acceptance Boundaries

The controller is a privileged **IAM provisioner**. It has no direct S3 object
read/write or EC2 start permission, but it can delegate bounded S3 authority by
changing personal roles and templates. That is indirect data authority; do
not treat the controller as an untrusted metadata-only component. Code updates,
SSM configuration, artifact replacement, boundary edits, and Lambda/IAM
administration must remain administrator-only. The boundary reduces the
delegation ceiling; it does not make arbitrary controller code safe.

For each release, run offline regressions and inspect policy/deployment diffs.
Use real member-credential RunInstances DryRun to check own-template/profile,
IMDSv2, allowed overrides, and foreign/tampered denial cases. Separately validate
the intended S3 role against disposable data and record the result privately.
DryRun does not launch hardware, prove SSH reachability, or establish that the
interactive member console flow has been tested. Real SSH/console/HPC acceptance
must be recorded separately; this automation does not deploy an HPC cluster.
