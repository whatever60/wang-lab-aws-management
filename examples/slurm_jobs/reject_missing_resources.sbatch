#!/bin/bash
#SBATCH --partition=cpu
#SBATCH --job-name=reject-missing-resources
#SBATCH --time=00:02:00
#SBATCH --output=reject_missing_resources_%x-%j.out

set -euo pipefail

echo "This job should be rejected by job_submit.lua before it starts."
