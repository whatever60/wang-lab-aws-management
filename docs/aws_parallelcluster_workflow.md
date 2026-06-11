# AWS ParallelCluster HPC Workflow

This is the current target path for the lab HPC workflow.

## Decision

Use AWS ParallelCluster with Slurm. Keep the testing structure simple:

```text
head/login:
  one combined instance
  r6a.xlarge for x86_64
  r7g.xlarge for arm64
  no separate ParallelCluster login node pool

/home:
  EFS, deleted with the test cluster

/scratch:
  FSx for Lustre SSD SCRATCH_2, deleted with the test cluster

users:
  generated from IAM groups lab_members and admin
  Diego_User excluded

compute:
  CPU and GPU queues
  On-Demand only
  MinCount 0 on every compute resource
  generated from live EC2 catalog and AWS Pricing API
  allowed catalog includes x86_64 and arm64
  active test cluster uses x86_64 only

Slurm:
  memory-aware scheduling enabled
  compute resources weighted by hourly price
  jobs without explicit CPU and memory requests are rejected unless they request
  one concrete EC2 instance type
```

AWS PCS is no longer active because its standing managed-service cost is not worth it
for this iteration. AWS Batch remains a future alternative for container-only pipelines.

## Commands

Describe the plan:

```bash
uv run python aws_hpc_workflow.py describe
```

List generated users:

```bash
uv run python aws_hpc_workflow.py list-users
```

Generate the ParallelCluster config from IAM, EC2, and pricing:

```bash
uv run python aws_hpc_workflow.py generate-config
uv run python aws_hpc_workflow.py generate-config --cluster-architecture x86_64
uv run python aws_hpc_workflow.py generate-config --cluster-architecture arm64
```

List allowed EC2 instance types from the live EC2 catalog and Pricing API:

```bash
uv run python aws_hpc_workflow.py list-instance-catalog
uv run python aws_hpc_workflow.py list-instance-catalog --active-cluster-only
```

Current snapshots from June 11, 2026 are saved at:

- `docs/parallelcluster_allowed_instance_catalog_current.txt`
- `docs/parallelcluster_active_x86_instance_catalog_current.txt`

Validate with ParallelCluster dry run:

```bash
uv run python aws_hpc_workflow.py execute-pcluster-dryrun
uv run python aws_hpc_workflow.py execute-pcluster-dryrun --cluster-architecture arm64
```

Create the test cluster:

```bash
uv run python aws_hpc_workflow.py create-cluster
uv run python aws_hpc_workflow.py create-cluster --cluster-architecture arm64
```

Delete the test cluster and tagged test storage:

```bash
uv run python aws_hpc_workflow.py delete-cluster
```

## Slurm Tests

Submit from the head/login node after the repo is available there:

```bash
sbatch examples/slurm_jobs/home_efs_smoke.sbatch
sbatch examples/slurm_jobs/scratch_fsx_smoke.sbatch
sbatch examples/slurm_jobs/cpu_python_smoke.sbatch
sbatch examples/slurm_jobs/mpi_hostname_smoke.sbatch
sbatch examples/slurm_jobs/gpu_nvidia_smoke.sbatch
sbatch examples/slurm_jobs/reject_missing_resources.sbatch
```

The final job should be rejected by `job_submit.lua` because it omits explicit
`--cpus-per-task` and `--mem`/`--mem-per-cpu`.

For a direct instance-type request, use the lab wrapper:

```bash
wanglab-sbatch --instance-type t3.micro examples/slurm_jobs/cpu_python_smoke.sbatch
```

`--instance-type` is mutually exclusive with `--cpus-per-task`, `--mem`,
`--mem-per-cpu`, and manual Slurm constraints. The wrapper translates it to a Slurm
constraint for the chosen EC2 instance type. It also checks
`/etc/wanglab/active_instance_types.txt`, which is generated from the active cluster
config, so an ARM request on the current x86_64 cluster is rejected immediately with a
clear message.

## Login Guardrails

The bootstrap applies aggregate per-user caps on the shared head/login node:

- `CPUQuota=200%` on each `user-UID.slice`
- `MemoryMax=16G` on each `user-UID.slice`
- `maxlogins=4`
- process, file-size, CPU-time, and open-file PAM limits

The systemd slice cap is per Linux UID, so opening multiple SSH sessions does not multiply
the CPU or memory allowance.

## Instance Selection

`aws_hpc_workflow.py generate-config` fetches:

- IAM users from groups in `config/aws_hpc_workflow_manifest.json`
- EC2 instance metadata from `describe-instance-types`
- regional availability from `describe-instance-type-offerings`
- Linux On-Demand hourly price from the AWS Pricing API

The full allowed catalog includes x86_64 and arm64 Linux-compatible On-Demand instance
types, including previous-generation and very small shapes such as `t1.micro` when AWS
still offers and prices them. Each generated cluster chooses one active architecture with
`--cluster-architecture`. ParallelCluster requires the head node, login nodes, and compute
resources in a cluster to use the same processor architecture, so an x86_64 cluster only
gets x86_64 compute resources and an arm64 cluster only gets arm64 compute resources.

The catalog excludes bare-metal EC2 instances. In AWS terms, bare metal means EC2 gives
the instance the whole physical server instead of a normal virtualized VM. That is useful
for some low-level hardware workloads, but it is more expensive and not needed for this
simple Slurm test cluster.

The catalog also requires one network card and excludes specialized families such as
Trainium, Inferentia, VT, FPGA, Mac, and HPC-only families. GPU resources are limited to
NVIDIA GPU families because the smoke test and ParallelCluster GPU health check use
NVIDIA tooling.

Within each queue, Slurm sees generated compute resources with memory-aware scheduling and
price-derived dynamic node priority. Within equivalent shapes, ParallelCluster uses
`AllocationStrategy: lowest-price` so EC2 can fall back among compatible instance types.
