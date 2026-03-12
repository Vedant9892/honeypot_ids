"""Generate a processed CSV dataset from the central honeypot logs."""

from __future__ import annotations

# This script serves as a utility to convert the raw JSONL logs collected from the honeypot services into a structured CSV format suitable for training machine learning models. It reads the raw events, extracts relevant features using the `feature_extraction` module, and writes the resulting dataset to disk. The output CSV includes both the original event metadata and the engineered features, along with a label indicating whether the event is benign or malicious based on its attack type. This dataset can then be used for training IDS classifiers or performing further analysis.

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
