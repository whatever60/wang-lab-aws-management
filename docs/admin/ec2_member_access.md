# Proposed Member EC2 Access

This is a migration proposal, not an applied policy. Replace broad member EC2,
ELB, Auto Scaling, and CloudWatch permissions only after existing personal and
shared workloads have explicit ownership. Administrators must choose approved
regions, instance types, project memberships, role ARNs, and budget thresholds;
this note does not select those values.

## Access Rules

- **Trusted ownership:** use `Owner=<exact IAM username>` and `Project=<approved
  project identifier>` on instances and their volumes, snapshots, images, network
  interfaces, and other supported billable resources. For IAM users, own-resource
  permissions can compare `aws:ResourceTag/Owner` with `${aws:username}`. Give
  shared-project access through a separately approved project role or statement;
  matching a freely chosen Project tag is not membership. Protect IAM principal
  tags, role trust, and `sts:TagSession` from member-controlled changes. Federated
  and service identities need an administrator-controlled principal-tag mapping
  instead of assuming `${aws:username}` exists. [AWS ownership example](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_ec2_tag-owner.html)
- **Tags at creation, protected afterwards:** require the caller's exact Owner
  and an authorized Project using `aws:RequestTag` on each supported create API.
  Require both keys and exact key casing with `aws:TagKeys`; an allowed-key list
  alone does not require tags. Permit protected `CreateTags` only during approved
  creation through `ec2:CreateAction`. Explicitly deny subsequent changes/deletion
  of Owner or Project, including spelling/case variants, except through a trusted
  administrative migration path. Otherwise a member could claim another resource
  or select an unauthorized project. [AWS tagging authorization](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/supported-iam-actions-tagging.html)
- **Separate inventory from mutation:** allow the Describe actions actually
  needed by the console/CLI, generally on `Resource="*"`. Inventory visibility
  can include other users' resource metadata; it must not imply mutation access.
  Allow explicitly selected lifecycle operations only on owned or authorized
  project resources. Check every participating resource for multi-resource
  operations such as volume attachment, copy, and launch; checking only the
  instance is insufficient. [EC2 authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html)
- **Constrain launches and resizing:** apply approved-region and instance-type
  allowlists to supported API/resource combinations. Cover RunInstances, instance
  type modification, launch templates, Spot/Fleet, and every allowed service that
  can launch capacity. Split RunInstances authorization across instances, volumes,
  approved AMIs, subnets, security groups, keys, and interfaces; do not apply an
  instance-only condition indiscriminately to all of them. Preserve the current
  explicit deny for per-volume EBS size **over 1024 GiB**, including supported
  create/resize paths. This is neither total storage nor a spend cap. [AWS launch-policy examples](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ExamplePolicies_EC2.html)
- **Close alternate paths:** ordinary members should use approved networking;
  reserve shared security-group changes, public ingress, EIP allocation, ELB,
  ASG, and unrestricted Fleet/launch-template administration for trusted operators
  until equivalent controls exist. Remove inherited broad allows that bypass the
  new rules, including the corresponding CloudWatch/service permissions. Permit
  `iam:PassRole` only for named least-privilege instance roles and
  `iam:PassedToService=ec2.amazonaws.com`; do not rely on role tags for PassRole.
  Prevent unrestricted profile reassociation, IAM policy/trust edits, AssumeRole,
  and SSM/automation paths that confer stronger infrastructure permissions.
  [AWS PassRole guidance](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html)

## Migration Without Interrupting Existing Work

1. Inventory effective user/group/role policies, resource dependencies, active
   jobs, and ownership gaps. Confirm owners with the responsible people; do not
   derive authority from an old Name tag or grant every member a shared project.
2. Administrators tag existing resources and record project memberships. Put
   unresolved/shared infrastructure behind explicit, reviewed resource exceptions
   with an owner and expiry. Keep a restricted administrative recovery path.
3. Build the complete candidate policy and test a pilot identity against tagged
   fixtures. Check all required actions/condition keys in the authorization
   reference. Tagging and allowed workflows must work before enforcement; merely
   attaching a narrower Allow alongside AmazonEC2FullAccess does not restrict it.
4. Migrate in stages, replacing conflicting broad grants only after each cohort
   passes acceptance. Watch authorization failures and CloudTrail, preserve policy
   versions for rollback, then retire temporary exceptions. This proposal changes
   neither existing AWS permissions nor S3 access.

## Acceptance Matrix

Use `simulate-custom-policy`/`simulate-principal-policy` with realistic principal,
request, resource, region, and tag context. Repeat deny cases with a competing
broad Allow to test intended guardrails, then use API DryRun where supported and
small disposable fixtures for real authorization checks.

| Scenario | Required result |
| --- | --- |
| Approved launch, Owner=self, authorized Project; all required resource tags | Allowed |
| Missing/forged Owner, unauthorized Project, or tag-key case variant | Denied |
| Own lifecycle action; other user's action; explicit shared-project action | Allowed; denied; allowed only for that membership |
| Overwrite/delete protected tags or self-edit principal/session project tags | Denied |
| Wrong region/type; larger type via modify/template/Fleet/ASG | Denied |
| Supported EBS create/resize at 1024 GiB; above 1024 GiB | Size guardrail permits boundary; denies excess |
| Unapproved PassRole/profile, shared SG ingress, EIP, ELB/ASG or SSM bypass | Denied |
| Required inventory; existing migrated shared workflow; unrelated S3 behavior | Preserved |

Activate Owner/Project cost-allocation reporting and agree alerts separately.
AWS Budgets is delayed and notifications/actions are not a hard spend ceiling.
For enforceable member allocations, route launch/start/resize through a broker or
scheduler that reserves capacity and enforces concurrency, runtime, and storage
limits; remove direct bypass permissions. Retained disks, snapshots, network
charges, and billing delay still prevent a simple guarantee of an exact final
dollar bill. [AWS budget timing and overspend limitations](https://docs.aws.amazon.com/cost-management/latest/userguide/bcm-lite-view-budget.html)
