"""SHAP integration placeholder for explaining IDS predictions."""

from __future__ import annotations

from typing import Any

from honeypot_ids.ids.feature_extraction import FEATURE_COLUMNS, extract_event_features

try:
    import shap
except ImportError:
    shap = None


class ShapExplainer:
    """Provide SHAP-compatible explanations when the dependency is available."""

    def __init__(self, model: Any | None = None) -> None:
        self.model = model

    def explain_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Return a placeholder explanation derived from extracted features."""
        features = extract_event_features(event)
        feature_values = {name: features[name] for name in FEATURE_COLUMNS}

        if shap is None or self.model is None:
            return {
                "method": "shap_placeholder",
                "available": False,
                "top_features": sorted(feature_values.items(), key=lambda item: item[1], reverse=True)[:3],
            }

        return {
            "method": "shap",
            "available": True,
            "message": "Attach a trained model background dataset to compute full SHAP values.",
            "top_features": sorted(feature_values.items(), key=lambda item: item[1], reverse=True)[:3],
        }
