# Launch an EC2 Instance

Use the normal AWS EC2 console in **US East (N. Virginia), `us-east-1`**, or
standard AWS CLI/SDK calls. Choose your image, instance type, SSH key, networking,
and storage as usual. **Launch instance works directly.** A personal launch
template, special tag set, or repository command is not required.

The account permits normal key-pair and security-group creation from the launch
wizard. Existing shared network infrastructure remains administrator-managed.
EC2 operations on your own resources are allowed by default; guardrails protect
other people's resources and shared account settings.
The existing account limits still apply: launches use `us-east-1`, and each EBS
volume is limited to 1024 GiB. RAM comes from the instance type; increasing an
EBS disk does not increase RAM.

Optional existing templates may still prefill settings, but they are not the
required entry point. Native CLI calls need no `--launch-template`, personal
instance-profile argument, or Owner/Project tag specifications.

## Automatic Ownership and S3 Access

The existing background controller reads successful AWS CloudTrail creation
records, records ownership on the instance and newly created disks/interfaces,
and attaches your bounded personal S3 instance profile when the instance has
no profile. You do not need to select a role or enter ownership tags.

S3 credentials become available after background reconciliation and IAM
propagation. An application starting immediately at first boot can run before
that finishes; synchronous first-boot S3 access is not guaranteed. The AWS CLI
and SDKs automatically use the temporary instance-role credentials once ready.
A healthy scheduled repair runs every five minutes, with event-driven runs in
between. AWS delivery and retries can add delay.

The role provides approved lab-bucket reads and writes to your personal home
bucket. Standard commands work on the instance, for example:

```bash
aws sts get-caller-identity
aws s3 ls s3://YOUR_HOME_BUCKET/
```

The role applies to processes and users that can access instance metadata, so
use this setup for personal instances. Existing machines and profiles are not
retroactively replaced. Leaving the member group disables the managed personal
role after reconciliation, including already-issued credentials after IAM
propagation.

## Tags and Resource Management

Normal Name and project-specific descriptive tags are available. Private
`wanglab:Owner` / `wanglab:CreatorUserId` provenance markers are maintained by
the backend.
Known resources owned by someone else or by the administrator cannot be
modified through member permissions. New untagged resources remain usable
while asynchronous attribution completes; this shared account is not strict
instantaneous tenant isolation.

Stop or terminate instances when finished, as usual. For an unexpected denial,
provide the region, resource ID, and AWS error code to an administrator.

Existing idle-stop alarms use sustained low CPU activity. They do not reliably
identify idle GPU or memory workloads and do not provide a spending ceiling.
