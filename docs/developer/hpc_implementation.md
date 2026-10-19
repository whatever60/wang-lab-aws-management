# HPC Implementation Notes

The HPC workflow lives in `src/aws_audit/hpc/workflow.py` and is exposed through:

```bash
uv run aws-audit hpc --help
```

## Inputs

- `config/hpc_workflow_manifest.json`: committed policy input with environment
  placeholders for site-specific values.
- `scripts/parallelcluster_create_lab_users.sh`: version-checked bootstrap and timer installer.
- `src/aws_audit/hpc/lifecycle.py`: public-key resolution, versioned S3 release publishing,
  conditional pointer updates, deployed-hook checks and explicit cluster-tagged SSM rollout.
- `src/aws_audit/hpc/user_sync.py`: standalone standard-library node reconciler, also
  used to validate administrator-side identity registries.
- `examples/slurm_jobs/`: storage, CPU, GPU, MPI-style, and rejection smoke tests.

## Generated Outputs

These files are generated locally and ignored:

- `config/parallelcluster_lab.yaml`
- `config/parallelcluster_active_instance_types.txt`

Catalog snapshots are also generated outputs and should stay out of git unless they are
small sanitized examples.

## Main Flow

1. Load and environment-expand the manifest.
2. Fetch current/admin IAM users and validate fixed `HpcUid` tags and Linux identity collisions.
3. Fetch EC2 instance metadata, regional offerings, and Linux On-Demand prices.
4. Filter instance types by policy, architecture, availability, price, and GPU vendor.
5. Generate ParallelCluster YAML and an active instance type allowlist.
6. Upload bootstrap assets for dry-run/create commands.

## Architecture Handling

The active cluster architecture defaults to `x86_64` and can be overridden:

```bash
uv run aws-audit hpc generate-config --cluster-architecture arm64
```

ParallelCluster requires head, login, and compute nodes in one cluster to use the same
processor architecture. The generator therefore filters compute resources to the active
architecture and selects the matching head/login instance type from the manifest.

## Validation

Offline tests:

```bash
uv run python -m unittest tests/test_hpc_workflow.py
```

AWS-touching validation remains opt-in:

```bash
uv run aws-audit hpc execute-pcluster-dryrun
```


## User lifecycle boundary

`generate-config` creates dynamic lifecycle hooks, not static `name:uid` arguments.
`publish-users` and `sync-users` are preview-only unless passed `--execute`. Membership
changes require publishing; on-node timers read the published registry without IAM
permissions. Registry tombstones preserve historical identity ownership across removals.
Read [Managed HPC user lifecycle](../admin/hpc_user_lifecycle.md) for migration, rollback,
staleness behavior, required permissions and storage-retention rules.

Run lifecycle tests without AWS or root account changes:

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_hpc*.py'
```

The filesystem/command tests simulate enrollment, revocation, migration conflicts,
checksum/version validation, concurrent publication protection, S3 outages, targeted
rollback, future-node hooks and test-deletion/production-retention cleanup guards.


## Disposable test storage

The committed manifest is a pre-alpha test configuration: EFS and FSx use `Delete`,
with `storage_management.purpose=test` and `allow_cleanup=true`. Successful normal
CloudFormation deletion removes the owned filesystems without an extra cleanup action.
`delete-cluster --cleanup-storage` and `cleanup-storage` explicitly request the fallback;
it selects only filesystems with the cluster/test/Delete tag combination. The rendered
test plan shows that explicit flag and preserves the selected manifest path.

For future production use, an ignored local override must select `purpose=production`,
`allow_cleanup=false` and `Retain` for both filesystems. Cleanup eligibility is validated
before a combined delete/cleanup request can issue any deletion command. Identity UID,
public-key approval, target trust and account synchronization checks are independent of
this test-storage choice and remain enabled.
