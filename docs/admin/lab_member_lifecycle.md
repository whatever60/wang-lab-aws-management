# Lab Member Lifecycle

IAM groups and user tags define lab membership and stable HPC identities. The
ignored local S3 manifest inventories every account user and bucket for access
reconciliation. Keep these sources consistent; neither tool creates the other's
users or buckets implicitly. The deployed member-access controller automatically
maintains S3-only instance roles from live
membership and ownership metadata.

Keep real rosters, resource names, account identifiers, and operational records in
ignored local configuration or outputs. Passwords, access-key secrets, and private
SSH keys belong in an owner-only local directory outside synced workspaces and
must never be committed. Public documentation uses examples only.

## Naming And Identity

For an example researcher:

- IAM user: `ExampleResearcher_User`
- S3 home bucket: `example-researcher`
- Linux user and personal EC2 key pair: `example_researcher`
- IAM group: `lab_members`
- IAM tags: `AccessRole=CurrentMember`, `HomeBucket=example-researcher`, and
  `HpcUid=<allocated-stable-uid>`

Allocate the UID after checking the full current and historical allocation. Never
derive it from alphabetical roster order or reuse a departed member's identity.
The HPC tooling rejects duplicate UIDs and normalized Linux names.

## Onboard A Current Member

Administrators create new S3 buckets; ordinary members use the existing buckets
assigned through this workflow. Member self-service EC2 creation remains native.

1. Confirm the recipient and intended member/project access.
2. Create the IAM user with the three tags and add it to `lab_members`.
3. Create a console login requiring a password reset. If programmatic access is
   needed, create and privately deliver the CLI credential separately from code.
4. Create a personal SSH key locally and import only the public key into EC2 in
   the deployment region. Tag the EC2 key pair `Owner=<iam-user>` and
   `Project=personal`. Multiple owned keys are supported. Keep each private key
   owner-readable only.
5. Create the home bucket with bucket-owner-enforced ownership, all public-access
   blocks, and default encryption matching the site's policy.
6. Tag it `BucketScope=User`, `BucketOwner=<iam-user>`, and
   `OwnerAccessRole=CurrentMember`; install the personal-bucket write guardrails.
7. Update the full local manifest and inspect `aws-audit s3-access plan`. If doing
   a targeted onboarding update, add only the new bucket/object ARNs to the
   approved-read and alumni-read policies while preserving all other statements.
8. Run `aws-audit member-access sync`, or use
   `aws-audit s3-access apply --sync-member-access` after reviewing the full
   manifest. Verify the bounded personal S3 role/profile; no template pointers
   or personally tagged SSH key are prerequisites for native EC2 creation.
9. Verify CLI identity, own-bucket read/write, approved reads, foreign write
   denial, console reset and SSH key presence. Use the member identity for a
   normal RunInstances DryRun with no template, special tags or profile.
10. When HPC is deployed, synchronize its managed roster using the
    [HPC lifecycle workflow](parallelcluster_hpc.md). EC2 keys alone do not
    install Linux SSH authorization.
11. Deliver credentials and the private key only to the confirmed recipient via
    the explicitly authorized channel. Members use normal EC2 **Launch
    instance** and standard CLI/SDK calls in `us-east-1`. Record delivery
    metadata without secrets.

[Native EC2 usage](../user/ec2_launch.md) needs no special launch procedure.
Ownership and personal S3 profile attachment run in the background for new
instances; existing machines and profiles are not retrofitted.

## Offboard To Alumni

1. Move the user from `lab_members` to `alumni`; set `AccessRole=Alumni` and retain
   the historical `HomeBucket` mapping.
2. Retag the home bucket's `OwnerAccessRole=Alumni` and update the full local S3
   manifest. Preserve approved reads and deny writes, including to the old home.
3. Run `aws-audit member-access sync` and verify the managed role has an explicit
   deny-all state. Automatic IAM
   event handling and the scheduled fallback also reconcile this state. Both
   existing role credentials and new EC2 role sessions lose authorization after
   IAM propagation; this is not an instantaneous revocation guarantee.
4. Publish the HPC roster change and synchronize managed nodes. Preserve the
   retired UID in roster history; do not delete home data or assign the identity
   to someone else.
5. Verify managed SSH authorization is revoked, existing managed sessions are
   handled, and current-member EC2 mutation permissions are lost. Any unmanaged
   legacy machines require their own account/key inventory and revocation.
6. Reconcile programmatic credentials and retention with the site's offboarding
   policy; a group move does not erase credentials or other access paths.

Revoking the instance role does not terminate an instance, remove Linux SSH keys,
or erase data already copied onto a machine. Handle those access paths in the
offboarding review.

Alumni retain the explicitly approved EC2 Describe operations. Other direct EC2
operations remain explicitly denied; see [S3 access](s3_access.md) for the policy
semantics and verification procedure.

## Verification

```bash
uv run python -m unittest discover -s tests
uv run aws-audit hpc list-users
uv run aws-audit s3-access plan --manifest config/s3_access_manifest.local.json
uv run aws-audit member-access plan --config config/member_access.local.json
```

Do not invent a scope for an unclassified bucket to make the full-account plan
pass. Establish ownership, workload dependencies, and intended access first. A
project bucket need not use a person's name and must not be deleted merely
because its management tags are missing.
