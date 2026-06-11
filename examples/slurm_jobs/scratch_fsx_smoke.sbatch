#!/bin/bash
#SBATCH --partition=cpu
#SBATCH --job-name=scratch-fsx-smoke
#SBATCH --time=00:10:00
#SBATCH --cpus-per-task=1
#SBATCH --mem=2G
#SBATCH --output=scratch_fsx_%x-%j.out

set -euo pipefail

work_dir="/scratch/${USER}/slurm-smoke-${SLURM_JOB_ID}"
mkdir -p "${work_dir}"

echo "job=${SLURM_JOB_NAME}"
echo "job_id=${SLURM_JOB_ID}"
echo "host=$(hostname)"
stat -f -c 'scratch_fs_type=%T' /scratch

python3 - "${work_dir}/payload.bin" <<'PY'
import hashlib
import pathlib
import sys


def main() -> None:
    """Write and verify a small deterministic scratch payload."""
    path = pathlib.Path(sys.argv[1])
    payload = (b"wanglab-fsx-scratch-smoke\n" * 4096)
    path.write_bytes(payload)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    print(f"payload_bytes={len(payload)}")
    print(f"sha256={digest}")


main()
PY

test -s "${work_dir}/payload.bin"
