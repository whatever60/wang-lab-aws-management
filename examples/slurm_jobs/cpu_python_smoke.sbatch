#!/bin/bash
#SBATCH --partition=cpu
#SBATCH --job-name=cpu-python-smoke
#SBATCH --time=00:05:00
#SBATCH --cpus-per-task=2
#SBATCH --mem=2G
#SBATCH --output=cpu_python_%x-%j.out

set -euo pipefail

echo "job=${SLURM_JOB_NAME}"
echo "job_id=${SLURM_JOB_ID}"
echo "host=$(hostname)"

srun --ntasks=1 python3 - <<'PY'
import math


def main() -> None:
    """Run a tiny CPU computation under Slurm."""
    total = 0.0
    for value in range(1, 200000):
        total += math.sqrt(value)
    print(f"cpu_total={total:.6f}")


main()
PY
