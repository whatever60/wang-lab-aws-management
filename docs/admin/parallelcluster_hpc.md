# ParallelCluster HPC

The HPC path uses AWS ParallelCluster with Slurm. The cluster has one combined
head/login node, EFS for `/home`, FSx for Lustre SSD for `/scratch`, and Slurm compute
resources with `MinCount: 0`.

## Architecture Choice

ParallelCluster requires one processor architecture per cluster. Choose it explicitly:

```bash
uv run aws-audit hpc create-cluster --cluster-architecture x86_64
uv run aws-audit hpc create-cluster --cluster-architecture arm64
```

The committed manifest maps:

- `x86_64` to `r6a.xlarge` for the head/login node
- `arm64` to `r7g.xlarge` for the head/login node

Compute resources are generated from the live EC2 catalog and Linux On-Demand pricing,
then filtered to the chosen architecture.

## Required Local Values

The committed manifest uses placeholders. Export real values before generating or
creating a cluster:

```bash
export PARALLELCLUSTER_ASSETS_BUCKET="your-assets-bucket"
export PARALLELCLUSTER_ASSETS_READ_POLICY_ARN="arn:aws:iam::<account-id>:policy/<policy-name>"
export HPC_SUBNET_ID="YOUR_HPC_SUBNET_ID"
export HPC_KEY_NAME="your-ec2-keypair"
export HPC_ALLOWED_IPS="<your-ip-cidr>"
```

These values must not be committed.

## Publish Users Before Provisioning

Follow [Managed HPC user lifecycle](hpc_user_lifecycle.md) to configure public-key
sources, enable bucket versioning, review a user registry and publish it. IAM group
membership plus fixed `HpcUid` tags determine eligibility. Nodes load the published
versioned registry and refresh it periodically. Publishing or synchronizing requires an
explicit `--execute`; cluster creation verifies that the published release is current.

## Generate And Validate

Describe the current plan:

```bash
uv run aws-audit hpc describe
uv run aws-audit hpc describe --cluster-architecture arm64
```

Generate local operational files:

```bash
uv run aws-audit hpc generate-config
```

This writes ignored generated files:

- `config/parallelcluster_lab.yaml`
- `config/parallelcluster_active_instance_types.txt`

Validate with a ParallelCluster dry run:

```bash
uv run aws-audit hpc execute-pcluster-dryrun
```

Dry runs upload bootstrap assets to the configured S3 assets bucket but do not create
cluster resources.

## Create And Delete

Create:

```bash
uv run aws-audit hpc create-cluster
```

Delete the cluster:

```bash
uv run aws-audit hpc delete-cluster
```

The production default is `Retain` for EFS and FSx; retained data is not automatically
reattached to a replacement cluster. The actual deployed policy controls deletion.
Storage cleanup is opt-in and requires a disposable test manifest and explicit matching
resource tags. See the lifecycle guide before migrating an existing cluster or deleting
storage.

## Login Guardrails

The head/login bootstrap applies aggregate per-user limits:

- `CPUQuota=200%`
- `MemoryMax=16G`
- `maxlogins=4`
- process, file-size, CPU-time, and open-file PAM limits

Systemd user slices make CPU and memory limits aggregate per Linux UID, so opening
multiple SSH sessions does not multiply a user's allowance.

## Slurm Submissions

Normal jobs must request CPU and memory:

```bash
sbatch --cpus-per-task 4 --mem 16G examples/slurm_jobs/cpu_python_smoke.sbatch
```

Direct EC2 instance type requests use the bootstrap wrapper:

```bash
aws-audit-sbatch --instance-type t3.micro examples/slurm_jobs/cpu_python_smoke.sbatch
```

`--instance-type` is mutually exclusive with explicit CPU/memory requests and manual
Slurm constraints. The wrapper checks `/etc/aws-audit/active_instance_types.txt`, which
is generated from the active cluster config, so cross-architecture requests fail before
submission.
