#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


CHECKSUM_MODULUS = 2**64


def parse_args() -> argparse.Namespace:
    """Parse command line arguments for the data preprocessing mock."""
    parser = argparse.ArgumentParser(
        description="Run a deterministic data-heavy CPU preprocessing mock."
    )
    parser.add_argument("--rows", type=int, default=1000)
    parser.add_argument("--columns", type=int, default=32)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def synthetic_value(row_index: int, column_index: int) -> int:
    """Return one deterministic pseudo-data value."""
    seed = row_index * 1103515245 + column_index * 12345 + 67890
    return (seed & 0xFFFFFFFF) % 1000


def build_summary(rows: int, columns: int) -> dict[str, object]:
    """Compute simple summary statistics over synthetic tabular data."""
    column_sums = [0 for _ in range(columns)]
    checksum = 0
    max_row_total = 0

    for row_index in range(rows):
        row_total = 0
        for column_index in range(columns):
            value = synthetic_value(row_index, column_index)
            column_sums[column_index] += value
            row_total += value
            checksum = (
                checksum * 1315423911 + value + row_index + column_index
            ) % CHECKSUM_MODULUS
        if row_total > max_row_total:
            max_row_total = row_total

    return {
        "job": "mock-data-preprocess",
        "rows": rows,
        "columns": columns,
        "column_sum_preview": column_sums[:5],
        "max_row_total": max_row_total,
        "checksum": checksum,
    }


def write_json(data: dict[str, object], path: Path) -> None:
    """Write JSON data to a path, creating parent folders first."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    """Run the data preprocessing mock."""
    args = parse_args()
    summary = build_summary(args.rows, args.columns)
    write_json(summary, args.output)
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
