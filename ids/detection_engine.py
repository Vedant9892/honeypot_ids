"""Runtime detection engine for scoring structured honeypot events with PyTorch."""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from honeypot_ids.ids.feature_extraction import FEATURE_COLUMNS, extract_event_features
from honeypot_ids.ids.models.model import IDSClassifier, build_label_maps
from honeypot_ids.logging.logger import get_logger

try:
    import torch
except ImportError:
    torch = None


class IntrusionDetectionEngine:
    """Load a trained model and score honeypot events."""

    def __init__(self, model_path: Path | None = None) -> None:
        self.logger = get_logger()
        self.label_to_index, self.index_to_label = build_label_maps()
        self.model_path = model_path or Path(__file__).resolve().parent / "models" / "ids_model.pt"
        self.model = None

        if torch is not None:
            self.model = IDSClassifier(input_size=len(FEATURE_COLUMNS), output_size=len(self.label_to_index))
            if self.model_path.exists():
                state = torch.load(self.model_path, map_location="cpu")
                self.model.load_state_dict(state)
            self.model.eval()

    def _vectorize(self, event: dict[str, Any]) -> list[float]:
        features = extract_event_features(event)
        return [float(features[column]) for column in FEATURE_COLUMNS]

    def predict_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Score a single event and cache the result for dashboard consumption."""
        features = self._vectorize(event)

        if torch is None or self.model is None:
            heuristic_label = event.get("attack_type", "benign") or "benign"
            prediction = {
                "predicted_label": heuristic_label,
                "confidence": 0.5,
                "features": dict(zip(FEATURE_COLUMNS, features)),
                "mode": "heuristic_fallback",
            }
            self.logger.cache_prediction(prediction)
            return prediction

        input_tensor = torch.tensor([features], dtype=torch.float32)
        with torch.no_grad():
            logits = self.model(input_tensor)
            probabilities = torch.softmax(logits, dim=1)[0]
            confidence, index = torch.max(probabilities, dim=0)

        prediction = {
            "predicted_label": self.index_to_label[int(index)],
            "confidence": float(confidence),
            "features": dict(zip(FEATURE_COLUMNS, features)),
            "mode": "pytorch",
        }
        self.logger.cache_prediction(prediction)
        return prediction


if __name__ == "__main__":
    sample_event = {
        "timestamp": "2026-03-10T00:00:00+00:00",
        "source_ip": "192.168.1.50",
        "service": "http",
        "event": "search_sql_injection_attempt",
        "attack_type": "sql_injection",
        "payload": "' OR 1=1 --",
        "metadata": {"request_rate": 0.5},
    }
    engine = IntrusionDetectionEngine()
    print(engine.predict_event(sample_event))
