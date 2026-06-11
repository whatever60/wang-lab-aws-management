#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    """Parse command line arguments for the GPU training mock."""
    parser = argparse.ArgumentParser(
        description="Run a deterministic GPU-shaped training mock."
    )
    parser.add_argument("--epochs", type=int, default=2)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--feature-count", type=int, default=128)
    parser.add_argument("--checkpoint", type=Path, required=True)
    return parser.parse_args()


def batch_loss(epoch: int, batch_index: int, feature_count: int) -> float:
    """Return a deterministic synthetic loss for one training batch."""
    accumulator = 0
    for feature_index in range(feature_count):
        value = (epoch + 1) * (batch_index + 3) * (feature_index + 5)
        accumulator += value % 9973
    return accumulator / (feature_count * 9973)


def train(epochs: int, batch_size: int, feature_count: int) -> dict[str, object]:
    """Run a small deterministic training loop."""
    epoch_losses: list[float] = []
    batches_per_epoch = max(1, batch_size)
    for epoch in range(epochs):
        loss_total = 0.0
        for batch_index in range(batches_per_epoch):
            loss_total += batch_loss(epoch, batch_index, feature_count)
        epoch_losses.append(loss_total / batches_per_epoch)

    return {
        "job": "mock-gpu-training",
        "gpu_required": True,
        "epochs": epochs,
        "batch_size": batch_size,
        "feature_count": feature_count,
        "final_loss": epoch_losses[-1],
        "epoch_loss_preview": epoch_losses[:5],
    }


def write_json(data: dict[str, object], path: Path) -> None:
    """Write JSON data to a path, creating parent folders first."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    """Run the GPU training mock."""
    args = parse_args()
    checkpoint = train(args.epochs, args.batch_size, args.feature_count)
    write_json(checkpoint, args.checkpoint)
    print(json.dumps(checkpoint, sort_keys=True))


if __name__ == "__main__":
    main()
