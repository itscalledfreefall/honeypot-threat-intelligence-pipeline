from __future__ import annotations

from typing import Any

from .classification import classify_event
from .ioc import extract_indicators
from .models import NormalizedEvent
from .risk import score_event_record


def build_event_record(event: NormalizedEvent) -> dict[str, Any]:
    """Create the base structured record used by pipeline outputs."""

    record = event.to_dict()
    record["indicators"] = extract_indicators(event)
    record["classification"] = classify_event(event)
    record["risk"] = score_event_record(record)
    return record
