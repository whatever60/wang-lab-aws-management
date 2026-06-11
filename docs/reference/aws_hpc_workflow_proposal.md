# Proposal: Extend the Current AWS EC2 + S3 Workflow with AWS-Native HPC-Style Compute

**Prepared:** June 4, 2026  
**Audience:** Engineering / Research / Infrastructure Management  
**Current baseline:** EC2 + S3 only  
**Proposed extension:** Scheduler-managed CPU/GPU/memory compute with shared active storage

---

## 1. Executive Summary

The current AWS workflow uses **EC2 for compute** and **S3 for durable storage**. This is simple and effective for individual or small-scale workloads, but it becomes harder to manage when the team needs to switch between CPU, GPU, and memory-heavy workloads while sharing the same underlying data.

I recommend extending the current workflow with an **AWS-native HPC-style approach**:

```text
Users submit jobs
      |
      v
Scheduler chooses CPU / GPU / memory compute
      |
      v
Instances start only when needed
      |
      v
Shared active data is available to all jobs
      |
      v
Results are written back to S3
```

This is not a custom workaround. AWS has native services and supported tools for this pattern, including **AWS Parallel Computing Service**, **AWS ParallelCluster**, **AWS Batch**, **FSx for Lustre**, **EFS**, **S3**, and EC2 CPU/GPU/memory instance families.

The main recommendation is:

```text
Keep S3 as the durable source of truth.
Add a scheduler for job placement.
Add shared active storage for jobs.
Use separate compute queues for CPU, GPU, and memory-heavy work.
Let compute scale up and down automatically.
```

---

## 2. Current State

The current architecture is approximately:

```text
EC2 instance(s)
  |
  |-- EBS root volume for OS, packages, conda envs, local config
  |
  |-- S3 bucket for datasets, outputs, backups, and artifacts
```

This works when one person manually manages one machine. It becomes fragile when the team needs different machine types for different phases of work.

### Current Pain Points

| Area | Current Issue |
|---|---|
| CPU/GPU switching | Users must manually stop, start, resize, or replace EC2 instances. |
| Shared disk data | EBS is not a general shared filesystem for multiple active instances. |
| GPU setup | GPU support depends on host-level NVIDIA drivers and kernel modules, not just conda envs. |
| Cost control | Expensive GPU or memory-heavy instances can be left running accidentally. |
| Reproducibility | A single mutable EC2 root disk can accumulate environment changes over time. |
| Scaling | Concurrent jobs are awkward without a scheduler. |
| Management overhead | Someone must decide which machine to start and how to attach data. |

---

## 3. Why Not Keep Manually Switching EC2 Instance Types?

For one person, manually stopping an EC2 instance, changing its instance type, and restarting it can be acceptable.

However, this does not scale well as a team workflow.

### Manual EC2 Switching Model

```text
Stop EC2
Change instance type
Start EC2
SSH in
Activate correct conda env
Run workload
Copy output to S3
Remember to stop EC2
```

This is simple, but it has hidden risks:

1. CPU and GPU environments can share the same root disk even though GPU support depends on host-level drivers.
2. OS/kernel updates done while using CPU mode can later break GPU mode.
3. A single instance cannot naturally run several jobs at once on different compute types.
4. Team members need to coordinate who is using the machine.
5. Large data movement may become inefficient if S3 is accessed directly for every active workload.

---

## 4. Why Not Build Around Moving One EBS Volume Between Instances?

Another possible approach is to keep multiple stopped instances and move a shared EBS data volume between them.

Example:

```text
CPU instance root volume       GPU instance root volume        -> shared EBS data volume
High-memory instance root vol  /
```

This is better than forcing every workload onto one root disk, because CPU and GPU machines can have separate OS configurations. However, it is still not ideal as a team platform.

### Limitations of the EBS-Attach Approach

| Limitation | Why It Matters |
|---|---|
| One active writer assumption | A normal EBS filesystem is not a shared multi-instance filesystem. |
| Same-AZ constraint | EBS volumes must be attached within the same Availability Zone. |
| Manual attach/detach | Users or scripts must safely unmount, detach, attach, and mount. |
| Operational fragility | Incorrect detachment can risk filesystem corruption or stale writes. |
| Poor scheduling model | It still does not answer “which job should run where?” |
| Limited concurrency | It is awkward when multiple users or jobs need data at the same time. |

For team workflows, this is usually an intermediate workaround rather than the target architecture.

---

## 5. Proposed Architecture

The proposed target is an AWS-native HPC/batch pattern:

```text
                           ┌────────────────────┐
                           │        Users        │
                           │ CLI / notebooks /   │
                           │ scripts / pipelines │
                           └─────────┬──────────┘
                                     │
                                     v
                           ┌────────────────────┐
                           │    Job Scheduler    │
                           │ Slurm / AWS Batch   │
                           └─────────┬──────────┘
                                     │
          ┌──────────────────────────┼──────────────────────────┐
          │                          │                          │
          v                          v                          v
┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│    CPU Queue      │      │    GPU Queue      │      │ High-Memory Queue│
│ c/m instance types│      │ g/p instance types│      │ r/x/u instances  │
└────────┬─────────┘      └────────┬─────────┘      └────────┬─────────┘
         │                         │                         │
         └─────────────────────────┼─────────────────────────┘
                                   v
                         ┌──────────────────┐
                         │ Shared Filesystem │
                         │ FSx Lustre / EFS  │
                         └────────┬─────────┘
                                  │
                                  v
                         ┌──────────────────┐
                         │        S3         │
                         │ durable datasets, │
                         │ results, artifacts│
                         └──────────────────┘
```

The key change is that users submit work to a scheduler instead of manually managing EC2 machines.

```text
Old model:
  “Which EC2 instance should I start?”

New model:
  “What resources does this job need?”
```

---

## 6. Recommended AWS Building Blocks

### 6.1 Scheduler Layer

There are three reasonable AWS-native options.

| Option | Best For | Notes |
|---|---|---|
| **AWS Batch** | Containerized scripts, ML jobs, analytics jobs, ETL, batch pipelines | Best first step if jobs can be packaged as containers. |
| **AWS Parallel Computing Service** | Managed Slurm-based HPC | Good when the team wants Slurm but does not want to manage the Slurm control plane. |
| **AWS ParallelCluster** | More configurable Slurm/HPC clusters | Good when the team wants infrastructure-as-code control over cluster details. |

### Recommendation

```text
If jobs are mostly scripts or containers:
  Start with AWS Batch.

If users already expect Slurm-style HPC workflows:
  Use AWS Parallel Computing Service or AWS ParallelCluster.
```

For many teams moving from EC2 + S3, the lowest-friction path is:

```text
AWS Batch + containers + S3 + FSx for Lustre or EFS
```

For research, simulation, multi-user HPC, MPI, or Slurm-native users, the better path is:

```text
AWS PCS or AWS ParallelCluster + Slurm + FSx for Lustre + S3
```

---

## 7. Storage Strategy

### 7.1 Keep S3 as the Durable Source of Truth

S3 should remain the long-term storage layer for:

```text
raw datasets
processed datasets
model checkpoints
job outputs
logs
artifacts
backups
```

The proposed architecture does not replace S3. Instead, it adds a better active working layer for compute.

### 7.2 Add Shared Active Storage

The team should add either **FSx for Lustre** or **EFS** depending on workload needs.

| Storage | Best For | Recommendation |
|---|---|---|
| **FSx for Lustre** | High-throughput ML, HPC, simulation, large datasets, GPU training, scratch space | Preferred for performance-heavy workloads. |
| **EFS** | Shared home directories, scripts, configs, moderate I/O, simpler shared filesystem needs | Good for general shared files and lower-operational-complexity workflows. |
| **EBS** | Root volumes and single-instance block storage | Keep for OS/root disks, not as the main shared data layer. |
| **S3** | Durable object storage and long-term source of truth | Keep as the primary durable storage layer. |

### Recommended Storage Pattern

```text
S3:
  Durable source of truth

FSx for Lustre:
  High-performance active dataset and scratch space

EFS:
  Optional shared home directories, scripts, configs, lightweight shared files

EBS:
  Root volumes for EC2 nodes and single-instance temporary storage
```

---

## 8. Compute Queue Design

Instead of one manually resized EC2 instance, define several compute queues.

### Example Queues

```text
cpu-small:
  General CPU jobs
  Lower-cost c/m families
  Spot allowed where safe

cpu-large:
  Larger CPU jobs
  More vCPUs
  Longer runtime

gpu-dev:
  Small GPU jobs
  Interactive experiments
  g-family instances

gpu-train:
  Larger training jobs
  p-family or high-end g-family instances

mem-large:
  Memory-heavy jobs
  r/x/u families
```

The user workflow becomes:

```text
Submit job -> scheduler selects queue -> compute starts -> job runs -> output saved -> compute stops
```

This is more manageable than asking users to remember which EC2 instance type to switch to.

---

## 9. Environment Strategy

The team should separate **data**, **code**, and **runtime environment**.

```text
Data:
  S3 + FSx/EFS

Code:
  Git repository, container image, or shared project directory

Runtime environment:
  CPU image/container
  GPU image/container
  memory-heavy image/container
```

### Why Conda Alone Is Not Enough

Conda is useful for Python dependency isolation, but it does not fully isolate machine-level dependencies such as:

```text
NVIDIA driver
kernel modules
nvidia-smi
CUDA driver interface
nvidia-container-toolkit
EFA libraries
AMI architecture
mount configuration
```

This is why CPU and GPU compute should ideally have separate tested machine images or containers.

### Recommended Runtime Pattern

```text
CPU queue:
  CPU AMI or CPU container
  CPU conda/env dependencies

GPU queue:
  GPU AMI or GPU container
  NVIDIA driver support
  CUDA/PyTorch/TensorFlow stack

Shared across queues:
  same S3 data
  same FSx/EFS mount
  same source code release
```

This avoids relying on a single mutable EC2 root volume to support every workload.

---

## 10. Cost-Control Strategy

The proposal should reduce cost by starting expensive machines only when jobs need them.

### Cost Controls

| Control | Benefit |
|---|---|
| Autoscaling queues | Instances start when jobs exist and stop when idle. |
| Separate CPU/GPU queues | CPU jobs do not accidentally run on expensive GPU nodes. |
| Spot instances | Useful for retryable or checkpointed jobs. |
| On-Demand instances | Better for urgent or non-interruptible jobs. |
| S3 durable storage | Avoids keeping large datasets only on live compute disks. |
| FSx/EFS active storage | Provides shared active access without moving EBS volumes around. |
| Tags and budgets | Helps attribute spend by team, project, or queue. |

### Recommended Cost Policy

```text
Use Spot for:
  retryable training
  batch preprocessing
  simulations with checkpointing
  non-urgent jobs

Use On-Demand for:
  production-critical jobs
  jobs that cannot tolerate interruption
  urgent GPU work
  first-time debugging
```

---

## 11. Proposed Migration Plan

### Phase 1: Standardize Current EC2 + S3 Usage

Goal: prepare the current workflow for scheduler-based execution without disrupting users.

Actions:

```text
1. Keep S3 as the official durable data source.
2. Organize S3 prefixes for raw data, processed data, checkpoints, logs, and outputs.
3. Separate root-disk state from project data.
4. Identify common job types:
   - CPU preprocessing
   - GPU training
   - memory-heavy analytics
   - postprocessing
5. Document current instance types and usage patterns.
6. Decide which workloads are interactive versus batch.
```

Deliverable:

```text
Documented current-state workflow and target job categories.
```

### Phase 2: Add Shared Active Storage

Goal: stop treating EBS as the shared data mechanism.

Actions:

```text
1. Add FSx for Lustre for high-performance active datasets, if needed.
2. Add EFS for shared scripts, home directories, or lightweight shared files, if needed.
3. Keep S3 as source of truth.
4. Keep EBS for root volumes and single-instance local storage only.
```

Deliverable:

```text
Shared filesystem available to CPU and GPU compute nodes.
```

### Phase 3: Introduce Scheduler and Queues

Goal: replace manual EC2 selection with job submission.

Path A — AWS Batch:

```text
AWS Batch
  |
  |-- CPU job queue
  |-- GPU job queue
  |-- memory-heavy job queue
  |
  |-- EC2 Spot / On-Demand compute environments
  |
  |-- S3 + FSx/EFS storage access
```

Path B — AWS PCS or AWS ParallelCluster:

```text
Slurm cluster
  |
  |-- login/head node
  |-- CPU partition
  |-- GPU partition
  |-- memory partition
  |
  |-- FSx for Lustre / EFS
  |-- S3 integration
```

Deliverable:

```text
Users submit jobs to CPU/GPU/memory queues instead of manually managing EC2 instances.
```

### Phase 4: Harden Reproducibility and Operations

Goal: make the system reliable enough for team use.

Actions:

```text
1. Define CPU and GPU base images or containers.
2. Pin major driver/runtime versions.
3. Add job logging to S3 or CloudWatch.
4. Add job output conventions.
5. Add budget alerts and queue limits.
6. Add IAM roles per job type.
7. Add documentation for job submission.
8. Add checkpoint/retry patterns for Spot jobs.
```

Deliverable:

```text
Repeatable, auditable, cost-controlled job execution.
```

---

## 12. Recommended MVP

The first implementation should be deliberately small.

### MVP Scope

```text
Keep:
  existing S3 bucket
  existing EC2 development workflow

Add:
  one scheduler
  one shared active filesystem
  three compute queues
```

### MVP Architecture

```text
S3:
  durable datasets and outputs

Shared active storage:
  FSx for Lustre for high-performance active data
  or EFS for simpler shared filesystem needs

Scheduler:
  AWS Batch if container-first
  AWS PCS / ParallelCluster if Slurm-first

Queues:
  cpu
  gpu
  high-memory

Compute:
  EC2 On-Demand for initial validation
  Spot after checkpointing/retry behavior is validated
```

### MVP User Experience

Old model:

```bash
stop instance
change instance type
start instance
ssh in
activate conda env
run script
copy results to S3
remember to stop instance
```

New model:

```bash
submit-job --queue gpu --script train_model.sh
```

or, for Slurm-style workflows:

```bash
sbatch --partition=gpu train_model.sh
```

The user does not need to know which EC2 instance was started. The scheduler handles that.

---

## 13. Manager-Level Benefits

### Operational Benefits

```text
Less manual EC2 management
Cleaner CPU/GPU separation
Reduced risk from driver and AMI conflicts
Better job tracking
Better cost attribution
Better support for multiple users
Cleaner path to scaling
```

### Financial Benefits

```text
GPU instances run only when GPU jobs exist
CPU jobs do not accidentally run on expensive GPU nodes
Spot can be introduced for fault-tolerant workloads
S3 remains the durable storage layer
Shared filesystem capacity can be sized for active workloads only
```

### Technical Benefits

```text
Users share data without moving EBS volumes
Compute environments are reproducible
Different job types use different instance families
CPU/GPU dependencies are isolated
Large jobs can scale beyond one manually managed EC2 instance
```

---

## 14. Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Users may resist job-submission workflow | Keep current EC2 workflow during transition and provide templates. |
| FSx/EFS adds another storage layer | Keep S3 as source of truth; treat shared filesystem as active working storage. |
| GPU jobs may require driver tuning | Use GPU-specific AMIs or containers and keep CPU/GPU queues separate. |
| Spot interruptions may break long jobs | Use Spot only for checkpointed or retryable jobs at first. |
| Cluster setup may be too heavy initially | Start with one scheduler, three queues, and one shared filesystem. |
| Cost visibility may be unclear | Add tags, queue names, budget alerts, and per-job logging from day one. |

---

## 15. Decision Recommendation

Adopt an AWS-native HPC-style workflow as an extension of the current EC2 + S3 setup.

Do **not** make the long-term architecture depend on manually moving EBS volumes between stopped instances.

Recommended target:

```text
S3 as durable storage
FSx for Lustre or EFS as shared active storage
Scheduler-managed CPU/GPU/memory queues
Separate CPU and GPU runtime environments
Autoscaling EC2 capacity
```

Specific recommendation:

```text
If jobs are mostly scripts or containers:
  AWS Batch + S3 + FSx for Lustre/EFS

If users want Slurm or traditional HPC behavior:
  AWS Parallel Computing Service or AWS ParallelCluster + S3 + FSx for Lustre/EFS
```

My preferred near-term path:

```text
Short-term:
  Keep current EC2 + S3 workflow for development.

Near-term:
  Add AWS Batch or Slurm queues for repeatable jobs.

Medium-term:
  Move serious CPU/GPU workloads to scheduler-managed compute.

Long-term:
  Treat manual EC2 instance switching as an exception, not the standard workflow.
```

---

## 16. Final Position

This proposal is not to “build our own HPC.” It is to use AWS-native HPC and batch building blocks to make the current EC2 + S3 workflow more scalable, safer, and cheaper.

The target operating model is:

```text
S3 stores the truth.
Shared filesystem feeds active jobs.
Scheduler chooses the right compute.
EC2 capacity appears only when needed.
CPU and GPU environments stay isolated.
```

---

## 17. References

- AWS Parallel Computing Service: https://aws.amazon.com/pcs/
- AWS PCS User Guide: https://docs.aws.amazon.com/pcs/latest/userguide/what-is-service.html
- AWS ParallelCluster Documentation: https://docs.aws.amazon.com/parallelcluster/
- What is AWS ParallelCluster: https://docs.aws.amazon.com/parallelcluster/latest/ug/what-is-aws-parallelcluster.html
- AWS Batch Documentation: https://docs.aws.amazon.com/batch/
- What is AWS Batch: https://docs.aws.amazon.com/batch/latest/userguide/what-is-batch.html
- Amazon FSx for Lustre: https://docs.aws.amazon.com/fsx/latest/LustreGuide/what-is.html
- FSx for Lustre and S3 data repositories: https://docs.aws.amazon.com/fsx/latest/LustreGuide/fsx-data-repositories.html
