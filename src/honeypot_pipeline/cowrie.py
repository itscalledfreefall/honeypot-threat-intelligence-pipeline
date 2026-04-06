from __future__ import annotations

import json
from collections.abc import Iterable, Iterator, Mapping
from typing import Any

from .models import NormalizedEvent


def _as_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize_cowrie_event(payload: Mapping[str, Any]) -> NormalizedEvent:
    """Map a Cowrie JSON event into the repository's normalized schema."""

    return NormalizedEvent(
        timestamp=payload.get("timestamp"),
        event_type=str(payload.get("eventid", "unknown")),
        honeypot="cowrie",
        source_ip=payload.get("src_ip"),
        source_port=_as_int(payload.get("src_port")),
        destination_ip=payload.get("dst_ip"),
        destination_port=_as_int(payload.get("dst_port")),
        protocol=payload.get("protocol"),
        session_id=payload.get("session"),
        username=payload.get("username"),
        password=payload.get("password"),
        command=payload.get("input") or payload.get("command"),
        url=payload.get("url"),
        raw_event=dict(payload),
    )


def iter_normalized_cowrie_events(lines: Iterable[str]) -> Iterator[NormalizedEvent]:
    """Yield normalized Cowrie events from a JSON-lines source."""

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON on line {line_number}") from exc

        if not isinstance(payload, dict):
            raise ValueError(f"Expected JSON object on line {line_number}")

        yield normalize_cowrie_event(payload)

