# Member EC2 Access

`aws_audit.ec2_access` builds complete IAM documents offline. Deployment is a
separate administrative operation: replace `AmazonEC2FullAccess` on the member
group with **every** generated document. Keep existing S3, password, and EBS
policies. A narrower Allow beside EC2FullAccess is not an effective restriction.
Do not attach these member Denies to the admin group.

The managed member deployment enables `member_launch`: members launch from
their four administrator-maintained personal templates, with a personal S3
profile and IMDSv2 already configured. See the
[member launch guide](../user/ec2_launch.md) and
[automation/role lifecycle](member_launch_automation.md). The base builder also
supports a legacy configuration without `member_launch`; that mode has no
profile/template exception and is not the managed console onboarding flow.

## Policy Contract

Members retain `ec2:Describe*` inventory in every region. In approved regions,
they can start, stop, reboot, and terminate their own instances; attach/detach
their own volumes to/from their own instances; delete/modify their own volumes;
and use/delete their own EC2 keys. Ownership is
`ec2:ResourceTag/Owner = ${aws:username}` for **IAM users**. Untagged or differently
owned resources fail closed. Project tags never establish shared membership.

New launches use exact approved AMIs, their reviewed backing snapshots, subnets,
and security groups. Administrators approve those inputs, including image
publisher and data contents; the builder cannot verify provenance offline.
Members import their own public key with `ImportKeyPair`, retain the private key
locally, and use SSH. Every new instance, volume, network interface, and imported
key requires **Owner = exact IAM username**, **Project = personal**. Only the
optional Name tag is also permitted, with exact key spelling. Members may update
only the descriptive Name tag on their owned instances, volumes, interfaces,
and keys. Owner, Project, all other tags, and tag deletion remain protected.
[AWS tagging authorization](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/supported-iam-actions-tagging.html)

RunInstances checks each participating resource separately. In managed mode,
it requires one of the caller's four protected template-ARN user pointers, a
template whose Owner matches the caller, the exact personal instance profile,
and IMDSv2. Current-member AccessRole, HomeBucket, and all four template pointers
must be present. It permits PassRole only for the caller's exact role under
`/wanglab/member-s3/`, passed to EC2. Members may override approved image/type
choices and choose another personally owned key; the final request still has
to satisfy every source, profile, ownership, and metadata constraint.

It denies existing ENI reuse, unapproved image/snapshot/network resources,
foreign or unpublished templates/profiles, Spot, and dedicated tenancy.
Without `member_launch`, all launch templates/profiles and PassRole are denied.
Blank extra volumes are allowed;
snapshot-backed launch volumes require an approved backing snapshot. Standalone
CreateVolume permits blank volumes only. Both sides of AttachVolume/DetachVolume
must be owned. Snapshot/image creation, copying, registration, sharing, imports,
and direct EBS block APIs are administrator-only to prevent cross-member data
access. New-resource tags never authorize claiming existing resources.
[AWS multi-resource semantics](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-policies-for-amazon-ec2.html),
[EC2 action/resource reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html)

RunInstances and StartInstances enforce the approved instance-type list.
Instance resize, user-data edits, metadata/profile changes, shared SG/network/EIP
changes, Fleet, launch templates, ELB, and Auto Scaling are administrator-only.
Explicit Denies reject other EC2 APIs even against competing broad Allows. The
bundle also denies PassRole outside the exact managed exception, new
service-linked roles, role assumption/session tagging, principal-tag edits, all
SSM APIs, EC2 Instance Connect, and alarm/metric writes that could start or
recover infrastructure. The EC2 bundle grants no S3 data access; the separate
personal instance role supplies bounded S3 permissions. Administrators retain
separate permissions.
[AWS PassRole requirements](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html)

The existing **1024 GiB per-volume** creation/resize Deny is retained and repeated
in the bundle. It never applies to StartInstances or normal attachment of a
legacy large volume. It does not cap aggregate disk usage, IOPS, throughput,
instance count, runtime, or spend. AWS Budgets notifications/actions are delayed;
a hard member allocation requires a broker or scheduler and removal of direct
launch/start bypasses.
[AWS budget limitations](https://docs.aws.amazon.com/cost-management/latest/userguide/bcm-lite-view-budget.html)

## Build a Reviewed Candidate

Keep live configuration and generated documents outside tracked source. JSON
configuration requires these fields; no infrastructure is inferred:

| Field | Administrative input |
| --- | --- |
| `account_id` | Exact commercial AWS account ID |
| `regions` | Approved mutation regions; normally `us-east-1` |
| `instance_types` | Exact approved types, including migrated existing types |
| `approved_image_arns` | Exact AMI ARNs, empty account component |
| `approved_snapshot_arns` | Reviewed AMI backing-snapshot ARNs, empty account component |
| `approved_subnet_arns` | Exact approved public subnets for SSH onboarding |
| `approved_security_group_arns` | Administrator-managed SSH SGs; members cannot edit ingress |
| `shared_grants` | Optional reviewed existing-instance lifecycle exceptions |
| `member_launch` | Managed template/profile mode with the exact protected paths and four pointer keys |

Enable the deployed console workflow with this additional object:

```json
{
  "member_launch": {
    "role_path": "/wanglab/member-s3/",
    "instance_profile_path": "/wanglab/member-s3/",
    "template_tag_keys": [
      "MemberLaunchUbuntu2404",
      "MemberLaunchAl2023",
      "MemberLaunchDL2204",
      "MemberLaunchDL2404"
    ],
    "require_template": true
  }
}
```

Only the administrator/controller writes those IAM user tags, whose values are
full template ARNs. Role and profile names must be the exact IAM username.
The controller creates all four templates and checks live membership, home
ownership, profile/role readiness, and owned key metadata before publishing the
pointers. A zero-key member stays pending. Multiple verified owned keys are
supported; a still-valid consistent default is retained, otherwise the first
sorted key name is used. Key-name similarity does not confer ownership.

Each shared grant contains `resource_arn`, `principal_arns`, `actions`,
`expires_at`, and `reason`. Use an exact same-account instance ARN and IAM user
ARNs; select only StartInstances, StopInstances, and/or RebootInstances; provide
an explicit UTC expiry, e.g. `2027-01-01T00:00:00Z`. Resolve any project group
membership administratively into these exact principals. The grant does not
authorize termination, disks, key use, launches, or tag edits. Expired grants deny
foreign access even against a broad Allow. A genuine owner's normal permission
survives expiry. Unresolved resources remain administrator-controlled.

```bash
umask 077
PYTHONPATH=src python -m aws_audit.ec2_access /private/reviewed-member-ec2.json > /private/member-ec2-policies.json
```

Output maps managed-policy names to complete documents, deterministically split
below IAM's 6144-character limit. Attach the **complete bundle together**; the
split only serves IAM size limits. The builder rejects more than six generated
attachments, leaving room for existing group policies under the default quota.
It makes no AWS calls, resolves no AMIs, and performs no deployment or tagging.

For offline inspection or a **legacy configuration without `member_launch`**,
the direct-request helper selects approved sources and emits all three
destination tag sets, without profiles, templates, or existing interfaces:

```bash
PYTHONPATH=src python -m aws_audit.ec2_access.launch /private/reviewed-member-ec2.json --username AliceUser --key-name AliceUserKey --instance-type t3.micro --name 'Personal instance' > /private/launch.json
aws ec2 run-instances --region us-east-1 --cli-input-json file:///private/launch.json --dry-run
```

Use an approved type and the exact caller username/owned imported key. The
helper prints its selected region, sources, and example command to stderr;
follow that region if the configuration contains several. Review the JSON and
require a successful DryRun before an explicitly authorized real launch. This
helper does not add a personal profile or template reference: its direct
request is intentionally denied by required-template mode. Use the published
personal templates for that mode.

## Launch from the AWS Console

Members open **EC2 → Launch Templates** in `us-east-1`, search
`wanglab-member-<exact IAM username>-`, and choose **Actions → Launch instance
from template** on the desired flavor's Default version. The four flavors are
Ubuntu 24.04, Amazon Linux 2023, and NVIDIA Ubuntu 22.04/24.04 deep learning
images. Required instance/volume/interface tags, the personal profile, owned
key, approved SG/subnet, public IPv4, and IMDSv2 are prefilled. Members do not
have to type three tag specifications. The
[user guide](../user/ec2_launch.md) describes allowed overrides and temporary S3
role credentials without storing personal AWS access keys on the instance.

Owner/Project, profile identity, template ownership, and the protected IAM
pointers are policy-enforced even if the console displays editable controls.
The console catalog is not automatically filtered to all approved sources and
types. Select an approved exact AMI rather than an SSM parameter; member SSM
access remains denied. Template maintenance and new SG/key creation inside
the launch wizard remain administrator-only; members can separately import a
properly tagged personal public key with the allowed ImportKeyPair API.

RunInstances DryRun and interactive console/SSH acceptance are separate checks.
Existing owned instances can still be started and stopped from the console
without adding request tags again.
[AWS console launch-template reference](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/launch-instances-from-launch-template.html)

## Migration and Acceptance

1. Inventory effective policies in every enabled region, active workloads, SSH
   paths, profiles, disks, and ownership evidence. Preserve running instances,
   network rules, and data. Removing IAM management permissions does not stop
   instances or invalidate existing SSH keys.
2. Administrators confirm owners from authoritative evidence and set canonical
   Owner/Project tags. Do not derive authority from Name tags, SSH key names, or
   ambiguous display names. Review an existing profile before granting its owner
   Start. Use exact expiring grants for reviewed migration cases; unresolved
   shared infrastructure remains admin-only.
3. Approve AMIs/root snapshots, common SSH SG, subnets, region, and types. Import
   and tag pilot public keys. Deploy the reviewed controller/boundary and
   required-template policy mode; confirm all four templates/profile/role and
   protected pointers. Generated templates supply TagSpecifications for
   **instance, volume, and network-interface**, each with Owner and Project.
   Preserve existing instance profiles; do not retrofit personal roles onto
   running or shared machines during this launch-policy migration.
4. Simulate **all** documents with real per-resource context, then test with the
   pilot's real credentials and `DryRun=True`: allowed requests return
   `DryRunOperation`, forbidden requests `UnauthorizedOperation`. Decode denial
   context to distinguish IAM denial from invalid input. Allow policy propagation
   time. Offline or missing-context simulations do not prove launches work.
5. Preserve previous policy versions and admin recovery. Attach the reviewed
   complete bundle, detach EC2FullAccess, and recheck each member's effective
   permissions, inventory, and mapped lifecycle actions. Do not stop/reboot active
   workloads merely to validate this migration.

| Acceptance case | Expected result |
| --- | --- |
| Own published template/profile, approved sources, owned key, IMDSv2, all three tag sets | Allowed on every participating resource |
| Direct launch in required-template mode, missing pointer, foreign template/profile | Explicit deny |
| Missing owned key; several verified owned keys | Pending with no pointer grant; active with deterministic/preserved owned default |
| Missing/forged Owner, non-personal Project, tag-key case variant | Explicit deny, even beside EC2FullAccess |
| Update only Name on own resource; rename foreign or unowned resource | Allowed; explicit deny |
| Direct Owner/Project/other tag update, lowercase name, or any tag deletion | Explicit deny, even beside EC2FullAccess |
| Existing foreign ENI, private AMI/snapshot, wrong SG/subnet | Explicit deny; repeat as real RunInstances DryRun |
| Own instance and own volume attachment; either resource foreign | Allowed; explicit deny |
| Owned Start with existing disk larger than 1024 GiB | Allowed if region/type approved |
| New/resize volume at 1024 GiB; 1025 GiB | Size guard permits boundary; explicit deny above it |
| Exact shared principal/resource/action before expiry; wrong/expired grant | Allowed; explicit deny |
| Wrong type/region, resize, template mutation/Fleet/ASG, foreign PassRole/profile, SG/EIP mutation | Explicit deny |
| Snapshot restore/copy, image registration, EBS block reads, SSM/Instance Connect | Explicit deny |
| Existing S3/password behavior and administrator recovery | Preserved through separate policies |

Offline regressions cover multi-resource decisions, deny precedence with a
competing broad Allow, tag protection, exact grants/expiry, and legacy large-disk
starts. AWS simulation and real DryRun remain deployment gates because an offline
evaluator cannot establish which request/resource context EC2 actually supplies.
Direct CreateTags needs an additional disposable-resource acceptance check:
update only Name on an owned test key, then verify Owner/Project changes are
denied. Live EC2 tagging authorization can expose an existing-resource context
without request-tag keys, which the IAM simulator does not reproduce. Creation
tag requirements therefore live on RunInstances/CreateVolume/ImportKeyPair;
direct protected-tag Denies use requested tag keys and the trusted create action.

Removing a member's launch pointers is only the new-launch control. The
[role lifecycle](member_launch_automation.md) also applies an explicit Deny-all
state to the managed personal role so already-issued instance credentials lose
S3 authority after IAM propagation. The event/five-minute repair loop is not a
hard instant-revocation SLA, and IAM group removal does not revoke Linux/SSH
access or change profiles on existing instances.
