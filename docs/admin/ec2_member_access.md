# Member EC2 Access

`aws_audit.ec2_access` builds complete IAM documents offline. Deployment is a
separate administrative operation: replace `AmazonEC2FullAccess` on the member
group with **every** generated document. Keep existing S3, password, and EBS
policies. A narrower Allow beside EC2FullAccess is not an effective restriction.
Do not attach these member Denies to the admin group.

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

RunInstances checks each participating resource separately. It denies existing
ENI reuse, unapproved image/snapshot/network resources, launch templates, Spot,
dedicated tenancy, and instance profiles. Blank extra volumes are allowed;
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
bundle also denies PassRole, new service-linked roles, role assumption/session
tagging, principal-tag edits, all SSM APIs, EC2 Instance Connect, and alarm/metric
writes that could start or recover infrastructure. It grants
no other service permissions. Administrators retain separate permissions.
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

Generate a compliant launch request from the same reviewed configuration. This
offline helper selects approved sources and emits all three destination tag
sets, without instance profiles, templates, or existing interfaces:

```bash
PYTHONPATH=src python -m aws_audit.ec2_access.launch /private/reviewed-member-ec2.json --username Alice_User --key-name alice_key --instance-type t3.micro --name 'Alice console' > /private/launch.json
aws ec2 run-instances --region us-east-1 --cli-input-json file:///private/launch.json --dry-run
```

Use an approved type and the exact caller username/owned imported key. The
helper prints its selected region, sources, and example command to stderr;
follow that region if the configuration contains several. Review the JSON and
require a successful DryRun before an explicitly authorized real launch.

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
   and tag a pilot public key. For RunInstances supply TagSpecifications for
   **instance, volume, and network-interface**, each with Owner and Project.
   The console's usual instance-only tags are insufficient; use a reviewed
   CLI/SDK request.
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
| Approved launch, owned key, all three destination tag sets | Allowed on every participating resource |
| Missing/forged Owner, non-personal Project, tag-key case variant | Explicit deny, even beside EC2FullAccess |
| Update only Name on own resource; rename foreign or unowned resource | Allowed; explicit deny |
| Direct Owner/Project/other tag update, lowercase name, or any tag deletion | Explicit deny, even beside EC2FullAccess |
| Existing foreign ENI, private AMI/snapshot, wrong SG/subnet | Explicit deny; repeat as real RunInstances DryRun |
| Own instance and own volume attachment; either resource foreign | Allowed; explicit deny |
| Owned Start with existing disk larger than 1024 GiB | Allowed if region/type approved |
| New/resize volume at 1024 GiB; 1025 GiB | Size guard permits boundary; explicit deny above it |
| Exact shared principal/resource/action before expiry; wrong/expired grant | Allowed; explicit deny |
| Wrong type/region, resize, LT/Fleet/ASG, PassRole/profile, SG/EIP mutation | Explicit deny |
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
