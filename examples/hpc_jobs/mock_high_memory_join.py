#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    """Parse command line arguments for the high-memory join mock."""
    parser = argparse.ArgumentParser(
        description="Run a deterministic high-memory join and aggregation mock."
    )
    parser.add_argument("--fact-rows", type=int, default=10000)
    parser.add_argument("--dimension-rows", type=int, default=1000)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def build_dimension_table(rows: int) -> dict[int, int]:
    """Build the dimension table retained in memory."""
    return {key: (key * 17 + 11) % 1000003 for key in range(rows)}


def aggregate_join(fact_rows: int, dimension_rows: int) -> dict[str, object]:
    """Join synthetic fact rows to the in-memory dimension table."""
    dimension = build_dimension_table(dimension_rows)
    total = 0
    checksum = 0
    for row_index in range(fact_rows):
        join_key = row_index % dimension_rows
        measure = (row_index * 31 + 7) % 1000003
        joined_value = measure * dimension[join_key]
        total += joined_value
        checksum = (checksum * 65537 + joined_value + join_key) % (2**64)

    return {
        "job": "mock-high-memory-join",
        "fact_rows": fact_rows,
        "dimension_rows": dimension_rows,
        "dimension_entries_in_memory": len(dimension),
        "joined_total": total,
        "checksum": checksum,
    }


def write_json(data: dict[str, object], path: Path) -> None:
    """Write JSON data to a path, creating parent folders first."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    """Run the high-memory join mock."""
    args = parse_args()
    summary = aggregate_join(args.fact_rows, args.dimension_rows)
    write_json(summary, args.output)
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
