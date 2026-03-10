"""LIME integration placeholder for local IDS prediction explanations."""

from __future__ import annotations

from typing import Any

from honeypot_ids.ids.feature_extraction import FEATURE_COLUMNS, extract_event_features

try:
    from lime.lime_tabular import LimeTabularExplainer
except ImportError:
    LimeTabularExplainer = None


class LimeExplainer:
    """Provide LIME-style local explanations when the dependency is available."""

    def __init__(self, model: Any | None = None) -> None:
        self.model = model

    def explain_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Return a placeholder local explanation for an event."""
        features = extract_event_features(event)
        feature_values = {name: features[name] for name in FEATURE_COLUMNS}

        if LimeTabularExplainer is None or self.model is None:
            return {
                "method": "lime_placeholder",
                "available": False,
                "top_features": sorted(feature_values.items(), key=lambda item: abs(item[1]), reverse=True)[:3],
            }

        return {
            "method": "lime",
            "available": True,
            "message": "Attach training data and prediction function to compute full LIME explanations.",
            "top_features": sorted(feature_values.items(), key=lambda item: abs(item[1]), reverse=True)[:3],
        }
