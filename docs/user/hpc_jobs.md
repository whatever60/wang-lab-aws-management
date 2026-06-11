# Submitting HPC Jobs

Use Slurm on the ParallelCluster head/login node for compute-heavy and data-heavy work.
The login node is for SSH, file editing, job submission, and cluster management; actual
pipelines should run through Slurm.

## Standard Resource Requests

Most jobs should request CPU and memory explicitly:

```bash
sbatch --cpus-per-task 8 --mem 32G my_pipeline.sbatch
```

Jobs without CPU and memory requests are rejected by the Slurm submit policy.

## Direct Instance Requests

If you know the exact EC2 instance type you want:

```bash
aws-audit-sbatch --instance-type c7i.2xlarge my_pipeline.sbatch
```

The wrapper checks the active cluster allowlist. If a user asks for an instance type that
does not exist in the current cluster architecture, the command fails before submission.

## Shared Storage

- `/home`: EFS-backed home directories.
- `/scratch`: FSx for Lustre scratch space for active high-throughput job data.
- `/local_scratch`: node-local ephemeral space.

Scratch is not a durable archive. Keep durable inputs and outputs in approved S3
locations or another managed durable store.

## Smoke Tests

Example Slurm scripts live in `examples/slurm_jobs/`:

```bash
sbatch examples/slurm_jobs/home_efs_smoke.sbatch
sbatch examples/slurm_jobs/scratch_fsx_smoke.sbatch
sbatch examples/slurm_jobs/cpu_python_smoke.sbatch
sbatch examples/slurm_jobs/mpi_hostname_smoke.sbatch
```

GPU validation is available when the GPU queue is enabled:

```bash
sbatch examples/slurm_jobs/gpu_nvidia_smoke.sbatch
```
