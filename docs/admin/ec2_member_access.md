# Member EC2 Access

Members use the normal AWS console, CLI and SDK. `aws_audit.ec2_access` builds
IAM documents offline; deploying **every** generated document replaces the
previous mandatory-template policy bundle on `lab_members`.

## Access Contract

EC2 is allowed by default. The policy does not maintain a list of permitted
EC2 operations. Explicit guardrails prevent changing known foreign resources,
damaging shared infrastructure, selecting another person's data role, changing
account defaults, and buying prepaid commitments. A new native EC2 feature does
not require a policy change merely because it was absent from a whitelist.

Native `RunInstances` does not require launch templates, IAM template-pointer
tags, a personal instance profile, Owner/Project request tags, approved AMI
registries, or an instance-type whitelist. Members select normal AWS images,
instance types, existing/default VPC networking and their SSH keys. Normal
key-pair and security-group creation is allowed in the launch wizard.

The controller separately attributes new resources from CloudTrail and attaches
a personal S3 role to profile-less new instances. A failure in S3 provisioning
must not block EC2 creation. See [background automation](member_launch_automation.md).

Private `wanglab:Owner` tags protect known foreign compute, storage, keys and
network resources against modification. Existing SSH keys and shared images,
snapshots, subnets and security groups remain usable as launch sources. Key
ownership never establishes the instance creator's identity or S3 permissions.
Members can create and manage
their own networks through normal AWS APIs. Untagged resources remain usable
during asynchronous attribution. Before migration, mark unresolved historical
resources with an administrator-owned `wanglab:Owner` value; do not infer a
personal owner from a display name. This account is a shared lab account, not
a hard tenant boundary during the attribution interval.

Members can use ordinary custom tags, including Owner/Project, at creation and
afterwards. Backend provenance markers are protected against direct edits;
only the controller/administrators can write markers that authorize automatic
profile attachment.

A member may supply only their exact personal S3 profile/role at launch.
Omitting it is valid. Members may associate their own personal role with their
own instance through the normal AWS interface. Passing another role and IAM
role administration are denied. Known shared infrastructure remains protected;
exact expiring Start/Stop/Reboot grants are still supported.

Snapshot deletion checks both the private owner and the actual AWS account
because snapshot ARNs omit the account component. Native snapshot/image
creation is permitted on mutable personal resources, with ownership recorded
in the background.

The primary-region guardrail and 1024 GiB per-volume EBS limit remain. This is
not a total storage, instance count, runtime or spending cap. Existing idle-stop
alarms are a separate control, with workload-dependent limitations. This EC2
policy neither grants unrelated services nor blanket-denies their existing
permissions. Account identity and personal S3 role administration stay protected.

## Configuration and Deployment

The normal policy configuration needs only the account and allowed regions:

```json
{
  "account_id": "111122223333",
  "regions": ["us-east-1"]
}
```

Optional `shared_grants` retain exact existing-instance exceptions with a
principal list, allowed Start/Stop/Reboot actions, UTC expiry and reason. Legacy
source/flavor inputs are accepted for optional existing templates, and do not
constrain native creation. Live account configuration belongs in ignored files.

```bash
PYTHONPATH=src python -m aws_audit.ec2_access config/member_access.local.json
```

Preserve previous default policy versions and exact group attachments for
rollback. Deploy the background controller before relaxing the member launch
policies. Reconcile historical unowned resources without changing workloads,
then attach every new policy and detach obsolete bundle documents and redundant
member-only EBS attachments after the new embedded volume guard is verified.

## Acceptance

Use real member credentials for native console-equivalent and CLI requests:
normal AMI/type/key, Name-only or no tags, no template and no profile. Creation
DryRuns must return `DryRunOperation`. Check new keys/groups, native custom tags,
foreign-resource/profile denial, region restrictions and the EBS size boundary.

A disposable real native instance must acquire verified creator tags and its
personal S3 role through the deployed controller, then use its instance
credentials for own-bucket access. Preserve explicit profiles and pre-cutover
machines. Verify offboarding disables managed-role access and that the test
instance, disk, key/group and probe objects are cleaned up.

[AWS native launch parameters](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-launch-parameters.html),
[AWS attaching a role after launch](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/attach-iam-role.html)
