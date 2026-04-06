from __future__ import annotations

from collections import Counter
from typing import Any, Mapping


class PipelineSummary:
    def __init__(self) -> None:
        self.total_events = 0
        self._source_ips: set[str] = set()
        self._attack_categories: Counter[str] = Counter()
        self._protocols: Counter[str] = Counter()
        self._event_types: Counter[str] = Counter()

    def add_record(self, record: Mapping[str, Any]) -> None:
        self.total_events += 1

        source_ip = record.get("source_ip")
        if isinstance(source_ip, str) and source_ip:
            self._source_ips.add(source_ip)

        classification = record.get("classification")
        if isinstance(classification, Mapping):
            category = classification.get("attack_category")
            if isinstance(category, str) and category:
                self._attack_categories[category] += 1

        protocol = record.get("protocol")
        if isinstance(protocol, str) and protocol:
            self._protocols[protocol] += 1

        event_type = record.get("event_type")
        if isinstance(event_type, str) and event_type:
            self._event_types[event_type] += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_events": self.total_events,
            "unique_source_ips": len(self._source_ips),
            "by_attack_category": dict(sorted(self._attack_categories.items())),
            "by_event_type": dict(sorted(self._event_types.items())),
            "by_protocol": dict(sorted(self._protocols.items())),
        }
