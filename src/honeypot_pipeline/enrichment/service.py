from __future__ import annotations

from typing import Any

from .abuseipdb import AbuseIPDBClient
from ..analysis.records import build_event_record
from ..analysis.risk import score_event_record
from ..models import NormalizedEvent
from .virustotal import VirusTotalClient


def _provider_failure(exc: Exception) -> dict[str, str]:
    return {
        "status": "failed",
        "error_type": type(exc).__name__,
        "message": str(exc),
    }


def _merge_score(providers: dict[str, dict[str, Any]]) -> dict[str, Any]:
    malicious_providers = [
        provider_name
        for provider_name, payload in providers.items()
        if payload.get("status") == "completed" and payload.get("is_malicious") is True
    ]
    provider_count = len(malicious_providers)

    if provider_count >= 2:
        confidence = "high"
    elif provider_count == 1:
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "is_malicious": provider_count > 0,
        "confidence": confidence,
        "malicious_provider_count": provider_count,
        "malicious_providers": malicious_providers,
    }


def enrich_event_with_threat_intel(
    event: NormalizedEvent,
    abuseipdb_client: AbuseIPDBClient | None = None,
    virustotal_client: VirusTotalClient | None = None,
    abuseipdb_malicious_threshold: int = 50,
    abuseipdb_max_age_in_days: int = 90,
    virustotal_malicious_threshold: int = 1,
) -> dict[str, Any]:
    record = build_event_record(event)

    if not event.source_ip:
        record["threat_intel"] = {
            "status": "skipped",
            "reason": "missing_source_ip",
            "providers": {},
        }
        return record

    providers: dict[str, dict[str, Any]] = {}

    if abuseipdb_client is not None:
        try:
            result = abuseipdb_client.lookup_ip(
                event.source_ip,
                max_age_in_days=abuseipdb_max_age_in_days,
            )
            score = result.abuse_confidence_score or 0
            providers["abuseipdb"] = {
                "status": "completed",
                "lookup_ip": event.source_ip,
                "malicious_threshold": abuseipdb_malicious_threshold,
                "is_malicious": score >= abuseipdb_malicious_threshold,
                "result": result.to_dict(),
            }
        except Exception as exc:
            providers["abuseipdb"] = _provider_failure(exc)

    if virustotal_client is not None:
        try:
            result = virustotal_client.lookup_ip(event.source_ip)
            malicious_count = (result.malicious or 0) + (result.suspicious or 0)
            providers["virustotal"] = {
                "status": "completed",
                "lookup_ip": event.source_ip,
                "malicious_threshold": virustotal_malicious_threshold,
                "is_malicious": malicious_count >= virustotal_malicious_threshold,
                "result": result.to_dict(),
            }
        except Exception as exc:
            providers["virustotal"] = _provider_failure(exc)

    completed_count = sum(1 for payload in providers.values() if payload.get("status") == "completed")
    failed_count = sum(1 for payload in providers.values() if payload.get("status") == "failed")

    if not providers:
        status = "not_requested"
    elif completed_count and failed_count:
        status = "partial"
    elif completed_count:
        status = "completed"
    else:
        status = "failed"

    record["threat_intel"] = {
        "status": status,
        "lookup_ip": event.source_ip,
        "providers": providers,
        "score": _merge_score(providers),
    }
    record["risk"] = score_event_record(record)
    return record


def enrich_event_with_abuseipdb(
    event: NormalizedEvent,
    client: AbuseIPDBClient,
    malicious_threshold: int = 50,
    max_age_in_days: int = 90,
) -> dict[str, Any]:
    return enrich_event_with_threat_intel(
        event,
        abuseipdb_client=client,
        abuseipdb_malicious_threshold=malicious_threshold,
        abuseipdb_max_age_in_days=max_age_in_days,
    )
