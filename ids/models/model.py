"""PyTorch model definitions for the honeypot intrusion detection system."""

from __future__ import annotations

from typing import Any

from honeypot_ids.logging.log_config import load_project_config

try:
    import torch.nn as nn
except ImportError:
    nn = None


def build_label_maps() -> tuple[dict[str, int], dict[int, str]]:
    """Load label mappings from configuration."""
    config = load_project_config()
    label_map = config.get("ids", {}).get("label_map", {"benign": 0, "malicious": 1})
    normalized = {str(label): int(index) for label, index in label_map.items()}
    reverse = {index: label for label, index in normalized.items()}
    return normalized, reverse


if nn is not None:

    class IDSClassifier(nn.Module):
        """Simple feed-forward classifier for binary or multi-class attack detection."""

        def __init__(self, input_size: int, output_size: int) -> None:
            super().__init__()
            hidden_one = max(16, input_size * 2)
            hidden_two = max(8, input_size)
            self.network = nn.Sequential(
                nn.Linear(input_size, hidden_one),
                nn.ReLU(),
                nn.Dropout(0.2),
                nn.Linear(hidden_one, hidden_two),
                nn.ReLU(),
                nn.Linear(hidden_two, output_size),
            )

        def forward(self, inputs: Any) -> Any:
            return self.network(inputs)

else:

    class IDSClassifier:  # type: ignore[override]
        """Fallback class used when PyTorch is not installed."""

        def __init__(self, input_size: int, output_size: int) -> None:
            self.input_size = input_size
            self.output_size = output_size

        def eval(self) -> None:
            return None
