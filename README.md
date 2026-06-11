# AWS Audit

Utilities for AWS inventory reporting, cost allocation, S3 access reconciliation,
audit alert setup, and AWS ParallelCluster/Slurm workflow management.

The repo now exposes one command:

```bash
uv run aws-audit --help
```

Common entry points:

```bash
uv run aws-audit inventory --help
uv run aws-audit monthly-costs --help
uv run aws-audit s3-access --help
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
- Generated operational files such as `config/parallelcluster_lab.yaml`,
  `config/parallelcluster_active_instance_types.txt`, catalog snapshots, outputs,
  and `site/` are ignored.

## Tests

Default tests are offline:

```bash
uv run python -m unittest discover -s tests
```

AWS-touching checks such as ParallelCluster dry runs are manual/opt-in.
