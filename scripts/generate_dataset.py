"""Generate a processed CSV dataset from the central honeypot logs."""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from honeypot_ids.ids.dataset_builder import build_dataset


def main() -> None:
    """Generate the processed CSV dataset."""
    path = build_dataset()
    print(f"Dataset generated at {path}")


if __name__ == "__main__":
    main()
