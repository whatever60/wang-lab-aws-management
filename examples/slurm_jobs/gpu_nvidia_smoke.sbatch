#!/bin/bash
#SBATCH --partition=gpu
#SBATCH --job-name=gpu-nvidia-smoke
#SBATCH --time=00:10:00
#SBATCH --cpus-per-task=2
#SBATCH --mem=4G
#SBATCH --gres=gpu:1
#SBATCH --output=gpu_nvidia_%x-%j.out

set -euo pipefail

echo "job=${SLURM_JOB_NAME}"
echo "job_id=${SLURM_JOB_ID}"
echo "host=$(hostname)"

nvidia-smi

python3 - <<'PY'
import subprocess


def main() -> None:
    """Print the first GPU name visible to the job."""
    output = subprocess.check_output(
        [
            "nvidia-smi",
            "--query-gpu=name,memory.total",
            "--format=csv,noheader",
        ],
        text=True,
    )
    print(output.strip())


main()
PY
