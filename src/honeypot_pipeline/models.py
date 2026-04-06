from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(slots=True)
class NormalizedEvent:
    """Common schema for events entering the analysis pipeline."""

    timestamp: str | None
    event_type: str
    honeypot: str
    source_ip: str | None
    source_port: int | None
    destination_ip: str | None
    destination_port: int | None
    protocol: str | None
    session_id: str | None
    username: str | None
    password: str | None
    command: str | None
    url: str | None
    raw_event: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert the dataclass into a JSON-serializable dictionary."""

        return asdict(self)

