# Mock HPC Jobs

These scripts are safe local stand-ins for future computation-heavy and data-heavy
AWS PCS/Slurm jobs. The defaults are intentionally small enough to run on a laptop.
The large AWS-shaped arguments live in `config/aws_hpc_workflow_manifest.json`.

Run local smoke tests:

```bash
uv run python examples/hpc_jobs/mock_data_preprocess.py \
  --rows 1000 \
  --columns 32 \
  --output outputs/mock_data_preprocess_summary.json

uv run python examples/hpc_jobs/mock_gpu_training.py \
  --epochs 2 \
  --batch-size 16 \
  --feature-count 128 \
  --checkpoint outputs/mock_gpu_training_checkpoint.json

uv run python examples/hpc_jobs/mock_high_memory_join.py \
  --fact-rows 10000 \
  --dimension-rows 1000 \
  --output outputs/mock_high_memory_join_summary.json
```
