from __future__ import annotations

from typing import Any

from .abuseipdb import AbuseIPDBClient
from .models import NormalizedEvent
from .records import build_event_record


def enrich_event_with_abuseipdb(
    event: NormalizedEvent,
    client: AbuseIPDBClient,
    malicious_threshold: int = 50,
    max_age_in_days: int = 90,
) -> dict[str, Any]:
    record = build_event_record(event)

    if not event.source_ip:
        record["threat_intel"] = {
            "provider": "abuseipdb",
            "status": "skipped",
            "reason": "missing_source_ip",
        }
        return record

    result = client.lookup_ip(event.source_ip, max_age_in_days=max_age_in_days)
    score = result.abuse_confidence_score or 0
    record["threat_intel"] = {
        "provider": "abuseipdb",
        "status": "completed",
        "lookup_ip": event.source_ip,
        "malicious_threshold": malicious_threshold,
        "is_malicious": score >= malicious_threshold,
        "result": result.to_dict(),
    }
    return record
