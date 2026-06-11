# AWS HPC Workflow MVP Implementation

This document adapts `docs/aws_hpc_workflow_proposal.md` into the current repo-local
testing implementation.

The current implementation follows this direction:

```text
Primary scheduler:
  AWS ParallelCluster using Slurm

Head/login:
  one instance with a 60 GiB encrypted gp3 root volume
  r6a.xlarge for x86_64
  r7g.xlarge for arm64
  no separate login node pool

Shared home:
  EFS mounted at /home
  deleted with the test cluster

Scratch:
  FSx for Lustre SSD SCRATCH_2 mounted at /scratch
  deleted with the test cluster

Users:
  IAM group lab_members plus IAM group admin
  Diego_User excluded

Compute:
  CPU and GPU Slurm queues
  On-Demand only
  generated from EC2 catalog and AWS Pricing API
  full allowed catalog includes x86_64 and arm64
  active generated cluster uses --cluster-architecture
  MinCount 0 on all compute resources
```

AWS PCS is no longer active for this iteration.

## Files

- `config/aws_hpc_workflow_manifest.json`: policy inputs for generation.
- `config/parallelcluster_wanglab.yaml`: generated ParallelCluster config.
- `scripts/parallelcluster_create_lab_users.sh`: user, login-limit, and Slurm submit-policy bootstrap.
- `examples/slurm_jobs/`: storage, CPU, GPU, MPI-style, and rejection smoke tests.
- `docs/aws_parallelcluster_workflow.md`: runbook.
- `aws_hpc_workflow.py`: helper CLI.
- `tests/test_aws_hpc_workflow.py`: offline unit tests.

## Commands

```bash
uv run python aws_hpc_workflow.py describe
uv run python aws_hpc_workflow.py describe --cluster-architecture arm64
uv run python aws_hpc_workflow.py list-users
uv run python aws_hpc_workflow.py list-instance-catalog
uv run python aws_hpc_workflow.py generate-config
uv run python aws_hpc_workflow.py generate-config --cluster-architecture arm64
uv run python aws_hpc_workflow.py execute-pcluster-dryrun
uv run python aws_hpc_workflow.py execute-pcluster-dryrun --cluster-architecture arm64
uv run python aws_hpc_workflow.py create-cluster
uv run python aws_hpc_workflow.py create-cluster --cluster-architecture arm64
uv run python aws_hpc_workflow.py delete-cluster
```

On the head/login node, regular jobs should submit with explicit Slurm resources:

```bash
sbatch --cpus-per-task 4 --mem 16G examples/slurm_jobs/cpu_python_smoke.sbatch
```

Direct EC2 instance requests use the lab wrapper:

```bash
wanglab-sbatch --instance-type t3.micro examples/slurm_jobs/cpu_python_smoke.sbatch
```

The wrapper makes `--instance-type` mutually exclusive with explicit CPU and memory
requests, checks the generated active instance allowlist at
`/etc/wanglab/active_instance_types.txt`, then passes the instance type to Slurm as a node
constraint. On the current x86_64 cluster, an arm64 instance type is rejected before
submission.

## Validation

Local tests:

```bash
uv run python -m unittest tests/test_aws_hpc_workflow.py
```

ParallelCluster dry-run validation currently succeeds with expected informational storage
deletion messages and EFA recommendations for larger GPU shapes.
