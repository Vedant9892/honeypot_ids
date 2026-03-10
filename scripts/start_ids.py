"""Run the IDS engine over recent logs in one-shot or watch mode."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from honeypot_ids.ids.dataset_builder import load_raw_events
from honeypot_ids.ids.detection_engine import IntrusionDetectionEngine


def score_latest_event(engine: IntrusionDetectionEngine) -> dict[str, object] | None:
    """Score the most recent log event if one exists."""
    events = load_raw_events()
    if not events:
        return None
    return engine.predict_event(events[-1])


def main() -> None:
    """Run the detection engine."""
    parser = argparse.ArgumentParser(description="Start the research IDS engine")
    parser.add_argument("--watch", action="store_true", help="Continuously score the latest event")
    parser.add_argument("--interval", type=int, default=5, help="Polling interval in seconds")
    args = parser.parse_args()

    engine = IntrusionDetectionEngine()

    if not args.watch:
        prediction = score_latest_event(engine)
        print(json.dumps(prediction or {"message": "No events available"}, indent=2))
        return

    while True:
        prediction = score_latest_event(engine)
        if prediction is not None:
            print(json.dumps(prediction, indent=2))
        time.sleep(max(args.interval, 1))


if __name__ == "__main__":
    main()
