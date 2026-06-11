#!/bin/bash
#SBATCH --partition=cpu
#SBATCH --job-name=home-efs-smoke
#SBATCH --time=00:05:00
#SBATCH --cpus-per-task=1
#SBATCH --mem=1G
#SBATCH --output=home_efs_%x-%j.out

set -euo pipefail

echo "job=${SLURM_JOB_NAME}"
echo "job_id=${SLURM_JOB_ID}"
echo "host=$(hostname)"
echo "user=$(whoami)"
echo "home=${HOME}"

test_file="${HOME}/parallelcluster-home-smoke-${SLURM_JOB_ID}.txt"
printf 'home smoke from %s job %s\n' "$(hostname)" "${SLURM_JOB_ID}" > "${test_file}"
test -s "${test_file}"
stat -f -c 'home_fs_type=%T' "${HOME}"
cat "${test_file}"
