# AWS Audit

Lab AWS access, personal EC2 launches, inventory and cost reports, audit alerts,
and optional ParallelCluster/Slurm test tooling.

Members use the ordinary AWS console, CLI and SDK. EC2 is allowed by default;
explicit guardrails protect other people's resources and shared account
settings. Ownership and personal S3 access are handled in the background, with
no required template, special tags or repository command.
S3 bucket creation is an explicit exception: administrators provision new
buckets, and ordinary members use existing lab buckets.

The repo now exposes one command:

```bash
uv run aws-audit --help
```

Common entry points:

```bash
uv run aws-audit inventory --help
uv run aws-audit monthly-costs --help
uv run aws-audit s3-access --help
uv run aws-audit member-access --help
uv run aws-audit audit-setup --help
uv run aws-audit hpc --help
```

## Install

```bash
uv sync
```

Docs are built locally with Material for MkDocs:

```bash
uv run mkdocs serve
uv run mkdocs build
```

The docs source lives in `docs/`; built HTML goes to ignored `site/`.

## Configuration

Committed config files are examples or templates. Real account IDs, buckets, ARNs,
subnets, key names, IP allowlists, and rosters should live in ignored local config
files or environment variables.

Examples:

- `config/hpc_workflow_manifest.json` uses environment placeholders for local
  ParallelCluster values.
- `config/s3_access_manifest.example.json` is a safe example. Copy it to ignored
  `config/s3_access_manifest.local.json` before running S3 reconciliation.
- `config/member_access.local.json` holds account/region, S3 boundary and native
  cutover configuration. The deployed function receives this nonsecret JSON
  directly; live IAM membership and bucket ownership tags remain authoritative.
- Generated operational files such as `config/parallelcluster_lab.yaml`,
  `config/parallelcluster_active_instance_types.txt`, catalog snapshots, outputs,
  and `site/` are ignored.

## Tests

Default tests are offline:

```bash
uv run python -m unittest discover -s tests
```

AWS-touching checks such as ParallelCluster dry runs are manual/opt-in.
