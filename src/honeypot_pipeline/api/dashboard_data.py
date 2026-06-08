from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..analysis.summary import PipelineSummary
from ..storage.database import Database


@dataclass(slots=True)
class DashboardDataset:
    records: list[dict[str, Any]]
    skipped_lines: int
    summary: dict[str, Any]


# ── Database-backed loading (primary) ────────────────────────────────────


def load_dataset_from_db(
    db_path: Path | str,
    source_ip: str | None = None,
    event_type: str | None = None,
    attack_category: str | None = None,
    protocol: str | None = None,
    malicious_only: bool = False,
) -> DashboardDataset:
    """Load dashboard data from the SQLite database."""
    db = Database(db_path)
    db.initialize()

    records, _ = db.query_events(
        source_ip=source_ip,
        event_type=event_type,
        attack_category=attack_category,
        protocol=protocol,
        malicious_only=malicious_only,
    )
    summary = db.get_summary()
    db.close()

    return DashboardDataset(records=records, skipped_lines=0, summary=summary)


# ── JSONL-backed loading (fallback) ─────────────────────────────────────


def _timestamp_sort_key(record: dict[str, Any]) -> tuple[int, str]:
    timestamp = record.get("timestamp")
    if isinstance(timestamp, str) and timestamp:
        return (1, timestamp)
    return (0, "")


def load_records(path: Path) -> tuple[list[dict[str, Any]], int]:
    records: list[dict[str, Any]] = []
    skipped_lines = 0

    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue

            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError:
                skipped_lines += 1
                continue

            if not isinstance(payload, dict):
                skipped_lines += 1
                continue

            record = dict(payload)
            record["_record_id"] = line_number
            records.append(record)

    records.sort(key=_timestamp_sort_key, reverse=True)
    return records, skipped_lines


def derive_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    summary = PipelineSummary()
    for record in records:
        summary.add_record(record)
    return summary.to_dict()


def load_summary(path: Path | None) -> dict[str, Any] | None:
    if path is None or not path.exists():
        return None

    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if not isinstance(payload, dict):
        raise ValueError("Summary file did not contain a JSON object")
    return payload


def load_dataset(records_path: Path, summary_path: Path | None = None) -> DashboardDataset:
    records, skipped_lines = load_records(records_path)
    summary = load_summary(summary_path) or derive_summary(records)
    return DashboardDataset(records=records, skipped_lines=skipped_lines, summary=summary)


# ── Filtering (works on in-memory records) ──────────────────────────────


def filter_records(
    records: list[dict[str, Any]],
    source_ip: str | None = None,
    event_type: str | None = None,
    attack_category: str | None = None,
    protocol: str | None = None,
    malicious_only: bool = False,
) -> list[dict[str, Any]]:
    filtered: list[dict[str, Any]] = []

    for record in records:
        if source_ip and record.get("source_ip") != source_ip:
            continue
        if event_type and record.get("event_type") != event_type:
            continue
        if protocol and record.get("protocol") != protocol:
            continue

        classification = record.get("classification")
        if attack_category:
            if not isinstance(classification, dict):
                continue
            if classification.get("attack_category") != attack_category:
                continue

        if malicious_only:
            threat_intel = record.get("threat_intel")
            if not isinstance(threat_intel, dict):
                continue
            score = threat_intel.get("score")
            if not isinstance(score, dict) or score.get("is_malicious") is not True:
                continue

        filtered.append(record)

    return filtered


def get_record_by_id(records: list[dict[str, Any]], record_id: int) -> dict[str, Any] | None:
    for record in records:
        if record.get("_record_id") == record_id:
            return record
    return None
