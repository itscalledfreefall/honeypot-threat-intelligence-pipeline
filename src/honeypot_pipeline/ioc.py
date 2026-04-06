from __future__ import annotations

from typing import Any

from .models import NormalizedEvent


def extract_indicators(event: NormalizedEvent) -> dict[str, list[Any]]:
    """Extract simple indicators from a normalized event."""

    indicators = {
        "ip_addresses": [],
        "usernames": [],
        "passwords": [],
        "commands": [],
        "urls": [],
    }

    if event.source_ip:
        indicators["ip_addresses"].append(event.source_ip)
    if event.username:
        indicators["usernames"].append(event.username)
    if event.password:
        indicators["passwords"].append(event.password)
    if event.command:
        indicators["commands"].append(event.command)
    if event.url:
        indicators["urls"].append(event.url)

    return indicators

