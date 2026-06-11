#!/bin/bash
#SBATCH --partition=cpu
#SBATCH --job-name=mpi-hostname-smoke
#SBATCH --time=00:10:00
#SBATCH --nodes=2
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=1G
#SBATCH --output=mpi_hostname_%x-%j.out

set -euo pipefail

echo "job=${SLURM_JOB_NAME}"
echo "job_id=${SLURM_JOB_ID}"
echo "nodes=${SLURM_JOB_NODELIST}"

srun --ntasks=2 /bin/hostname | sort | uniq -c
