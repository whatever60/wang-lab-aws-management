# Lab Member Lifecycle

IAM groups and user tags define lab membership and stable HPC identities. The
ignored local S3 manifest inventories every account user and bucket for access
reconciliation. Keep these sources consistent; neither tool creates the other's
resources implicitly.

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

1. Confirm the recipient and intended member/project access.
2. Create the IAM user with the three tags and add it to `lab_members`.
3. Create a console login requiring a password reset. If programmatic access is
   needed, create and privately deliver the CLI credential separately from code.
4. Create a personal SSH key locally and import only the public key into EC2 in
   the deployment region. Keep the private key owner-readable only.
5. Create the home bucket with bucket-owner-enforced ownership, all public-access
   blocks, and default encryption matching the site's policy.
6. Tag it `BucketScope=User`, `BucketOwner=<iam-user>`, and
   `OwnerAccessRole=CurrentMember`; install the personal-bucket write guardrails.
7. Update the full local manifest and inspect `aws-audit s3-access plan`. If doing
   a targeted onboarding update, add only the new bucket/object ARNs to the
   approved-read and alumni-read policies while preserving all other statements.
8. Verify the new CLI identity, own-bucket read/write, approved-bucket reads,
   other-bucket write denial, console reset requirement, and public-key presence.
9. When HPC is deployed, publish and synchronize its managed roster using the
   [HPC lifecycle workflow](parallelcluster_hpc.md). EC2 key-pair existence alone
   does not install a key on a Linux account. Review node targets and deployment
   prerequisites before executing synchronization.
10. Deliver credentials and the private key only to the confirmed recipient via
    the explicitly authorized channel. Record delivery metadata without secrets.

The current member compute permissions are a separate policy decision. Review
the [EC2 member access proposal](ec2_member_access.md) before tightening them.

## Offboard To Alumni

1. Move the user from `lab_members` to `alumni`; set `AccessRole=Alumni` and retain
   the historical `HomeBucket` mapping.
2. Retag the home bucket's `OwnerAccessRole=Alumni` and update the full local S3
   manifest. Preserve approved reads and deny writes, including to the old home.
3. Publish the HPC roster change and synchronize managed nodes. Preserve the
   retired UID in roster history; do not delete home data or assign the identity
   to someone else.
4. Verify managed SSH authorization is revoked, existing managed sessions are
   handled, and current-member EC2 mutation permissions are lost. Any unmanaged
   legacy machines require their own account/key inventory and revocation.
5. Reconcile programmatic credentials and retention with the site's offboarding
   policy; a group move does not erase credentials or other access paths.

Alumni retain the explicitly approved EC2 Describe operations. Other direct EC2
operations remain explicitly denied; see [S3 access](s3_access.md) for the policy
semantics and verification procedure.

## Verification

```bash
uv run python -m unittest discover -s tests
uv run aws-audit hpc list-users
uv run aws-audit s3-access plan --manifest config/s3_access_manifest.local.json
```

Do not invent a scope for an unclassified bucket to make the full-account plan
pass. Establish ownership, workload dependencies, and intended access first. A
project bucket need not use a person's name and must not be deleted merely
because its management tags are missing.
