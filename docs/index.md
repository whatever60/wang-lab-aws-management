# AWS Audit Docs

This documentation covers local tooling for:

- AWS inventory reports
- EC2 compute cost allocation
- S3 access reconciliation
- audit alert setup
- AWS ParallelCluster and Slurm workflows

The docs are intended for three audiences:

- lab users running jobs and reports
- admins managing AWS resources
- developers maintaining the repo

## Local Commands

```bash
uv run aws-audit --help
uv run mkdocs serve
```

No public publishing is required. `mkdocs serve` starts a local documentation site.

## Configuration Rule

Do not commit real account-specific values. Use environment variables or ignored local
config files for account IDs, bucket names, ARNs, subnets, key names, IP allowlists,
Slack IDs, and real rosters.
