"""Training entry point for the PyTorch-based honeypot IDS model."""

from __future__ import annotations

import csv
import random
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from honeypot_ids.ids.feature_extraction import FEATURE_COLUMNS
from honeypot_ids.ids.models.model import IDSClassifier, build_label_maps
from honeypot_ids.logging.log_config import load_project_config, resolve_project_path

try:
    import torch
    from torch import nn
    from torch.utils.data import DataLoader, TensorDataset
except ImportError:
    torch = None
    nn = None
    DataLoader = None
    TensorDataset = None


def load_csv_dataset(dataset_path: Path) -> tuple[list[list[float]], list[int]]:
    """Load feature vectors and labels from the processed CSV dataset."""
    label_to_index, _ = build_label_maps()
    features: list[list[float]] = []
    labels: list[int] = []

    with dataset_path.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            label = row.get("label", "benign")
            if label not in label_to_index:
                continue
            features.append([float(row[column]) for column in FEATURE_COLUMNS])
            labels.append(label_to_index[label])

    return features, labels


def train_model(dataset_path: str | None = None) -> Path:
    """Train the IDS model and persist it to disk."""
    if torch is None or nn is None or DataLoader is None or TensorDataset is None:
        raise RuntimeError("PyTorch is required to train the IDS model")

    config = load_project_config()
    dataset = resolve_project_path(dataset_path or "data/processed/honeypot_dataset.csv")
    output_path = Path(__file__).resolve().parent / "ids_model.pt"
    learning_rate = float(config.get("ids", {}).get("learning_rate", 0.001))
    epochs = int(config.get("ids", {}).get("epochs", 10))
    batch_size = int(config.get("ids", {}).get("batch_size", 32))
    train_split = float(config.get("ids", {}).get("train_split", 0.8))

    features, labels = load_csv_dataset(dataset)
    if not features:
        raise ValueError("Dataset is empty. Generate features from honeypot logs before training.")

    combined = list(zip(features, labels))
    random.shuffle(combined)
    split_index = max(1, int(len(combined) * train_split))
    train_rows = combined[:split_index]

    train_x = torch.tensor([row[0] for row in train_rows], dtype=torch.float32)
    train_y = torch.tensor([row[1] for row in train_rows], dtype=torch.long)

    dataset_tensor = TensorDataset(train_x, train_y)
    dataloader = DataLoader(dataset_tensor, batch_size=min(batch_size, len(dataset_tensor)), shuffle=True)

    label_to_index, _ = build_label_maps()
    model = IDSClassifier(input_size=len(FEATURE_COLUMNS), output_size=len(label_to_index))
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)

    model.train()
    for _ in range(epochs):
        for batch_x, batch_y in dataloader:
            optimizer.zero_grad()
            logits = model(batch_x)
            loss = criterion(logits, batch_y)
            loss.backward()
            optimizer.step()

    torch.save(model.state_dict(), output_path)
    return output_path


if __name__ == "__main__":
    model_path = train_model()
    print(f"Model saved to {model_path}")