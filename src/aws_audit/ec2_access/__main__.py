"""Offline JSON policy generation; deliberately has no deployment command."""

import argparse
import json
import sys
from pathlib import Path

from .policy import build_policy_bundle, config_from_mapping


def main() -> None:
    parser = argparse.ArgumentParser(description="Build ALL member EC2 policy documents from a reviewed JSON configuration; no AWS calls")
    parser.add_argument("config", type=Path)
    args = parser.parse_args()
    try:
        config = config_from_mapping(json.loads(args.config.read_text(encoding="utf-8")))
        bundle = build_policy_bundle(config)
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))
    json.dump(bundle, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
