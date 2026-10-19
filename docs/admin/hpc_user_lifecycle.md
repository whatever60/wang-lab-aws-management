# Managed HPC user lifecycle

This workflow is for the ParallelCluster v3 `lab-hpc` configuration. It does not install
accounts on personal EC2 instances or migrate the old ParallelCluster v2 stack. Creating
an IAM user or importing an EC2 key alone does not enable HPC login.

## Identity and public keys

Current membership is the union of the configured IAM groups, restricted to users tagged
`AccessRole=CurrentMember` or `AccessRole=Admin`. Alumni and untagged users are excluded;
there are no person-specific exclusions. Every selected member needs an explicit, unique
integer `HpcUid` between 2001 and 60000. Linux names are derived from IAM names and must
be unique and at most 32 characters. UID 2000 is reserved for the `hpc-users` group.
Missing/invalid UIDs and name/UID collisions stop the batch. Never renumber a member or
reuse a departed member's UID or Linux name: EFS ownership uses numeric UIDs.

Each active member must have an explicitly approved public-key source **and** a
`public_key_sha256` pin in the administrator's ignored local manifest. There is no
implicit trust of an EC2 key-pair name, key-pair ID, or first-seen key: members with
broad EC2 permissions could replace those public keys. Confirm the initial key and
every rotation through a trusted member/administrator channel before setting its pin.
Set `user_lifecycle.public_key_sources`, for example:

```json
{
  "Alice_User": {
    "ec2_key_name": "alice_legacy_key",
    "public_key_sha256": "<approved-64-character-lowercase-hex-digest>"
  },
  "Bob_User": {
    "local_public_key_path": "/approved/public-keys/bob.pub",
    "public_key_sha256": "<approved-64-character-lowercase-hex-digest>"
  }
}
```

Choose exactly one source per member. EC2 sources are read using
`describe-key-pairs --include-public-key` in the cluster's region and must match the
approved pin. Local `.pub` files must be regular, not symlinks/hardlinks, owned by the
administrator or root, and not group/other writable. Parent directories must also be
administrator/root controlled and non-symlinks; a root-owned sticky temporary ancestor
is supported. Use a real absolute path if a platform's `/var` or other alias is a symlink.
Authorized-key options, multiline input and private-key formats are rejected;
`ssh-keygen -l` additionally validates public-key structure. No private key is derived
or required. Missing, changed, or malformed keys stop publication and preserve the
previous release.

The pin is SHA-256 hex of the normalized `algorithm base64` OpenSSH line **without**
a comment or trailing newline, rather than the `SHA256:` fingerprint of the binary
key blob. Compute it from an already independently approved `.pub` file:

```bash
uv run python -c 'import sys; from pathlib import Path; from aws_audit.hpc.user_sync import public_key, digest; print(digest(public_key(Path(sys.argv[1]).read_text()).encode("utf-8")))' /approved/public-keys/member.pub
```

Keep the manifest and public-key directory under administrator control. Do not
automatically accept a replacement EC2 key by copying its new digest into the manifest.

## Publication and existing-node synchronization

The assets bucket must have S3 versioning **Enabled**, with lifecycle deletion of registry
versions disabled for the required audit/rollback retention period. An administrator
must provision that setting; these commands do not enable it implicitly. Only the
administrator/publisher can write the `parallelcluster-assets/users/` prefix. Node roles
receive the exact read-only policy in
`config/parallelcluster_assets_read_policy.template.json`, including `GetObjectVersion`.
Do not grant members permission to write the roster or executable assets.

Prepare and inspect a public-only preview:

```bash
uv run aws-audit hpc --manifest config/hpc.local.json publish-users
```

The preview prints a stable `preview_sha256`. Review its registry, source pins, code
hashes, destination, and previous-release ETag, then explicitly approve that digest:

```bash
uv run aws-audit hpc --manifest config/hpc.local.json publish-users --execute \
  --approved-preview-sha256 <reviewed-preview-sha256>
```

The default preview path is ignored `outputs/hpc/users-preview.json`, containing a
public-only review envelope with the registry and the above approval inputs. No passwords,
AWS access keys or private SSH keys are written there. Execution rechecks those inputs,
rejects any change, and never overwrites the reviewed preview. A changed roster, key,
pin/source, code, destination, or current release requires a new preview and approval.
Publication uploads a versioned
user registry and content-addressed Python/bootstrap code, then updates `current.json`
last. That pointer pins every object version and SHA-256. Its write uses the previous
ETag (`If-Match`), or `If-None-Match: *` on first publication. A concurrent publisher
causes `PreconditionFailed`; fetch/review/retry instead of forcing an overwrite. Any
orphan immutable objects from that failed attempt grant no access.

Absent users are kept as inactive tombstones with their former UID/name and no public
keys. Tombstones cannot disappear or be reassigned. Key rotation follows the same
prepare/publish/sync process. For a planned offboarding, publish the tombstone promptly
and execute synchronization; simply changing IAM is not an automatic on-node revocation.

Preview the exact running/stopped cluster-tagged nodes, then synchronize:

```bash
uv run aws-audit hpc --manifest config/hpc.local.json sync-users
uv run aws-audit hpc --manifest config/hpc.local.json sync-users --execute
```

Ordinary `parallelcluster:cluster-name` and `parallelcluster:node-type=HeadNode|Compute`
tags only select candidates; they are not the trust boundary. Discovery obtains the
authoritative head instance ID and CloudFormation stack ARN from `pcluster describe-cluster`,
requires a stable stack, and traverses its real nested-stack resources. The head must
match both the ParallelCluster ID and a CFN-owned EC2 instance. Compute nodes must have
an AWS-protected `aws:ec2launchtemplate:id` belonging to that stack graph, a protected
launch-template version tag, and the exact ARN/ID of a trusted cluster instance profile
(CFN-owned, or containing a CFN-owned role). A forged ordinary tag, personal launch
template, or substituted profile aborts the entire rollout before SSM dispatch.
Deployments with externally managed profiles must expose the corresponding trusted
role through the cluster's CFN graph; do not weaken validation to accept arbitrary ARNs.
It refuses stopped nodes and any target not SSM Online. Start or retire stopped nodes
through a separately authorized operation before migration. It verifies that the
**deployed** head and every compute queue already use the reviewed dynamic bootstrap;
this prevents successful synchronization of today's nodes while tomorrow's compute
nodes still use an old static user list. Commands are version/hash checked, carry the
reviewed roster revision, and are awaited individually. A partial failure raises an
error with SSM command IDs; inspect and retry every failed target. SSM delivery is not
an atomic transaction across machines.

The publisher needs IAM group/tag reads, EC2 public-key reads, S3 versioning/read/write
permissions and `ssh-keygen`. The rollout operator additionally needs ParallelCluster
describes, CloudFormation `ListStackResources` across the cluster's nested stacks,
IAM `GetInstanceProfile` (or `ListInstanceProfilesForRole` for the supported external-profile
case), EC2/SSM describes,
`ssm:SendCommand` for the intended nodes and `GetCommandInvocation`. Nodes need Python 3,
AWS CLI, systemd, OpenSSH, standard Linux account tools, access to the versioned assets,
and an active systemd/snap SSM agent service. Generated head and compute roles explicitly
include `AmazonSSMManagedInstanceCore` in addition to the restricted asset-read policy.
Agent installation and HTTPS endpoint access remain AMI/network prerequisites; bootstrap
fails before account changes if the agent service is not active. Add policies to the existing
node role; `setup_ssm_for_instance.sh` replaces an instance profile and is not a migration
tool. No per-user AWS credentials are deployed to nodes.

## First installation and legacy migration

Before creating a new cluster, publish its user release. `create-cluster` and its dry run
check that IAM membership, public keys, head limits and local code match the published
release. Generated `OnNodeConfigured` actions reference content-addressed bootstrap
code and the dynamic `current.json` URI, rather than freezing usernames in YAML.

On an existing cluster, take a maintenance window and save its current configuration.
Replace only the head and each Slurm queue's `CustomActions.OnNodeConfigured` with the
`--sync-users <current-uri> <cluster-name> head|compute` action produced by this checkout.
Keep its existing networking, storage IDs, queues and instance catalog. Use the official
`pcluster update-cluster` dry run and update workflow, including compute-fleet stop/start
requirements where applicable. Do not regenerate an entire live configuration merely
to add a user. `sync-users --execute` checks the resulting deployed hooks by reading
`describe-cluster`'s HTTPS `clusterConfiguration.url`; it never prints the presigned URL.

Existing local accounts are **not** adopted automatically. To adopt an intended legacy
account, add its IAM name to `user_lifecycle.adopt_existing_users` in the administrator's
local manifest and review that explicit migration grant. Its local name, UID, primary
GID 2000 and `/home/<name>` must match; its EFS home must have the same UID. Adoption
preserves its password, shell and account-expiry settings, so resolve a legacy locked or
non-login account manually before enabling it. The migration never runs `usermod -u`,
recursively changes home ownership, deletes home data, or touches an unrelated account.
UID/home conflicts require a deliberate administrator data migration.

A node-local root-owned provenance file tracks exactly which accounts this tool owns.
The SSH configuration uses `Match Group hpc-users User <managed names>` and root-owned
`/etc/aws-audit/authorized_keys/%u`, with password/interactive authentication, external
key commands and certificate-based bypass disabled. It checks each active user's
effective `sshd -T` configuration. Unadopted group members keep their existing policy.
Users cannot add access back by editing EFS `~/.ssh/authorized_keys`; those data files
are preserved but ignored for managed users. A new node does not create inactive users
from leftover EFS homes. The local `/etc/passwd` identity still has to be created on each
node even though `/home` is shared. EFS must be mounted as NFSv4 before any enrollment. Home
ownership checks and creation are serialized across nodes by per-user NFSv4 advisory
locks in root-owned mode-0700 `/home/.aws-audit-hpc-locks`. Lock files are mode 0600;
symlinks, unsafe ownership/permissions and lock waits over 30 seconds are rejected.
The lock covers both `mkdir` and `chown`, so another node cannot mistake a partially
initialized home for an identity conflict. Existing directories/data are never replaced.

## Revocation, failures and audit

Each installed node synchronizes immediately and every two minutes (up to 15 seconds
jitter) through `aws-audit-hpc-users.timer`. Bootstrapped future nodes fetch the latest
versioned registry. A valid inactive record removes that member's local managed keys,
locks/expires the account, sets `nologin`, terminates its sessions/processes, and on the
head cancels its queued/running Slurm jobs. It retains the account's numeric identity
and all home data. Publish and push urgent removals; a powered-off or unreachable
machine cannot acknowledge immediate revocation.

A temporary S3/network/control-plane failure keeps the last valid access and existing
jobs. It grants no new access and fails visibly in systemd/SSM. The explicit default
staleness policy is `on_fetch_failure=retain`, with a warning after 3600 seconds since
the last successful sync. No elapsed-time policy automatically kills all members' jobs.
Last-success time, registry digest and staleness policy are recorded locally. Monitor
failed units/SSM results and the `HPC_USERS_FETCH_FAILED`/`HPC_USERS_STALE` journal messages;
staleness is an operational alert, not proof that IAM and node permissions still agree.

Malformed registries or identity conflicts do not lock out unrelated valid members.
Verified tombstones are applied independently of new-account enrollment conflicts.
If an enrollment fails after creating/reactivating an account, the reconciler rolls
back only that attempt's new grants and preserves previous valid users' keys/jobs.
Failed legacy adoption restores its old SSH policy rather than terminating its jobs.
Any rollback/Slurm cancellation failure is explicit and needs administrator attention.
Code-version/checksum failures preserve the last valid access and reject new grants;
roll out a reviewed release with SSM after updating future-node hooks.

Useful checks on each node:

```bash
sudo systemctl status aws-audit-hpc-users.timer aws-audit-hpc-users.service
sudo journalctl -u aws-audit-hpc-users.service --since '1 hour ago'
sudo cat /var/lib/aws-audit/hpc-last-success.json
```

Head limits are aggregate per UID: CPU 200%, memory 16G, four logins plus PAM limits.
PAM CPU time is written in minutes and file size in KiB; active user slices receive the
same limits immediately. IAM/CloudTrail and SSM provide operator/change evidence; Linux
SSH/user identity and Slurm logs provide the actual job submitter. EC2 instance-creator
ARNs do not identify the individual user behind scheduler-driven launches. This package
does not implement Slurm job-cost allocation.

## Retained storage

Production manifests now default both EFS and FSx to `Retain`. Deleting the cluster
preserves storage according to its **deployed** configuration; changing a local manifest
does not retroactively change an older cluster's deletion policy. Retained storage is
not automatically reattached by a newly generated cluster; explicitly reuse the saved
filesystem IDs when rebuilding. FSx scratch storage still needs a durable S3 archive.

`delete-cluster` does not invoke storage cleanup by default. Explicit cleanup requires
all of: an administrator's test manifest with `purpose=test`, `allow_cleanup=true`, both
storage policies `Delete`, and resource tags for the matching cluster plus
`aws-audit:storage-purpose=test` and `aws-audit:storage-lifecycle=Delete`. Untagged legacy
resources and resources marked `Retain` are never selected. Do not retag production
storage as disposable to work around this check.
