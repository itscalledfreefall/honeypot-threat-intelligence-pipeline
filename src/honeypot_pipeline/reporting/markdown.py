from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ..analysis.risk import risk_level, score_event_record
from ..api.dashboard_data import load_dataset
from ..storage import write_json_document


def is_record_malicious(record: dict[str, Any]) -> bool:
    threat_intel = record.get("threat_intel")
    if not isinstance(threat_intel, dict):
        return False

    score = threat_intel.get("score")
    if not isinstance(score, dict):
        return False

    return score.get("is_malicious") is True


def get_malicious_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [record for record in records if is_record_malicious(record)]


def _confidence_rank(value: str | None) -> int:
    mapping = {"high": 3, "medium": 2, "low": 1}
    return mapping.get((value or "").lower(), 0)


def _confidence_label(rank: int) -> str:
    if rank >= 3:
        return "high"
    if rank == 2:
        return "medium"
    if rank == 1:
        return "low"
    return "unknown"


def _record_risk(record: dict[str, Any]) -> tuple[int, str]:
    risk = record.get("risk")
    if isinstance(risk, dict):
        score = int(risk.get("score") or 0)
        level = str(risk.get("level") or risk_level(score))
        return score, level

    computed = score_event_record(record)
    score = int(computed.get("score") or 0)
    level = str(computed.get("level") or risk_level(score))
    return score, level


def build_blocklist_entries(
    records: list[dict[str, Any]],
    source_ip: str | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    prefix = source_ip.strip() if isinstance(source_ip, str) else ""

    for record in records:
        ip = record.get("source_ip")
        if not isinstance(ip, str) or not ip:
            continue
        if prefix and not ip.startswith(prefix):
            continue

        risk_score, _ = _record_risk(record)
        classification = record.get("classification")
        category = None
        if isinstance(classification, dict):
            raw_category = classification.get("attack_category")
            if isinstance(raw_category, str) and raw_category:
                category = raw_category

        bucket = grouped.setdefault(
            ip,
            {
                "ip": ip,
                "total_event_count": 0,
                "malicious_event_count": 0,
                "threat_score": 0,
                "risk_score_total": 0,
                "top_attack_category": "unknown",
                "attack_category_counts": {},
                "attack_category_max_risk": {},
                "last_seen": None,
                "confidence_rank": 0,
            },
        )
        bucket["total_event_count"] += 1

        if not is_record_malicious(record):
            continue

        bucket["malicious_event_count"] += 1
        bucket["threat_score"] = max(bucket["threat_score"], risk_score)
        bucket["risk_score_total"] += risk_score

        timestamp = record.get("timestamp")
        if isinstance(timestamp, str) and timestamp:
            last_seen = bucket.get("last_seen")
            if not isinstance(last_seen, str) or timestamp > last_seen:
                bucket["last_seen"] = timestamp

        threat_intel = record.get("threat_intel")
        confidence = None
        if isinstance(threat_intel, dict):
            score = threat_intel.get("score")
            if isinstance(score, dict):
                raw_confidence = score.get("confidence")
                if isinstance(raw_confidence, str):
                    confidence = raw_confidence
        bucket["confidence_rank"] = max(
            bucket["confidence_rank"],
            _confidence_rank(confidence),
        )

        if category:
            counts = bucket["attack_category_counts"]
            max_risks = bucket["attack_category_max_risk"]
            counts[category] = counts.get(category, 0) + 1
            max_risks[category] = max(max_risks.get(category, 0), risk_score)

    entries: list[dict[str, Any]] = []
    for bucket in grouped.values():
        malicious_event_count = int(bucket["malicious_event_count"])
        if malicious_event_count == 0:
            continue

        category_counts = bucket["attack_category_counts"]
        category_max_risk = bucket["attack_category_max_risk"]
        top_attack_category = "unknown"
        if category_counts:
            top_attack_category = sorted(
                category_counts,
                key=lambda item: (
                    -int(category_counts[item]),
                    -int(category_max_risk.get(item, 0)),
                    item,
                ),
            )[0]

        threat_score = int(bucket["threat_score"])
        avg_risk_score = round(bucket["risk_score_total"] / malicious_event_count, 1)
        entries.append(
            {
                "ip": bucket["ip"],
                "total_event_count": int(bucket["total_event_count"]),
                "malicious_event_count": malicious_event_count,
                "threat_score": threat_score,
                "avg_risk_score": avg_risk_score,
                "risk_level": risk_level(threat_score),
                "top_attack_category": top_attack_category,
                "confidence": _confidence_label(int(bucket["confidence_rank"])),
                "last_seen": bucket["last_seen"],
            }
        )

    entries.sort(key=lambda item: item["ip"])
    entries.sort(key=lambda item: item["last_seen"] or "", reverse=True)
    entries.sort(key=lambda item: float(item["avg_risk_score"]), reverse=True)
    entries.sort(key=lambda item: int(item["malicious_event_count"]), reverse=True)
    entries.sort(key=lambda item: int(item["threat_score"]), reverse=True)
    if limit is not None:
        return entries[:limit]
    return entries


def collect_blocklist_ips(records: list[dict[str, Any]]) -> list[str]:
    return [entry["ip"] for entry in build_blocklist_entries(records)]


def build_markdown_report(
    records: list[dict[str, Any]],
    summary: dict[str, Any],
    blocklist_ips: list[str],
) -> str:
    malicious_records = get_malicious_records(records)
    lines = [
        "# Honeypot Threat Intelligence Report",
        "",
        "## Summary",
        "",
        f"- Total events: {summary.get('total_events', 0)}",
        f"- Unique source IPs: {summary.get('unique_source_ips', 0)}",
        f"- Malicious events: {len(malicious_records)}",
        f"- Blocklist candidates: {len(blocklist_ips)}",
        "",
        "## Risk Levels",
        "",
    ]

    risk_levels = summary.get("by_risk_level", {})
    if isinstance(risk_levels, dict) and risk_levels:
        for key, value in risk_levels.items():
            lines.append(f"- {key}: {value}")
    else:
        lines.append("- none")

    lines.extend(
        [
            "",
            "## Attack Categories",
            "",
        ]
    )

    categories = summary.get("by_attack_category", {})
    if isinstance(categories, dict) and categories:
        for key, value in categories.items():
            lines.append(f"- {key}: {value}")
    else:
        lines.append("- none")

    lines.extend(
        [
            "",
            "## Blocklist Candidates",
            "",
        ]
    )

    if blocklist_ips:
        for ip in blocklist_ips:
            lines.append(f"- {ip}")
    else:
        lines.append("- none")

    lines.extend(
        [
            "",
            "## Recent Malicious Events",
            "",
        ]
    )

    if malicious_records:
        for record in malicious_records[:10]:
            risk = record.get("risk") if isinstance(record.get("risk"), dict) else {}
            lines.append(
                f"- `{record.get('timestamp', '-')}` `{record.get('source_ip', '-')}` "
                f"`{record.get('event_type', '-')}` risk `{risk.get('level', 'unknown')}`"
            )
    else:
        lines.append("- none")

    lines.append("")
    return "\n".join(lines)


def export_report_bundle(records_file: Path, summary_file: Path | None, output_dir: Path) -> dict[str, Path]:
    dataset = load_dataset(records_file, summary_file)
    output_dir.mkdir(parents=True, exist_ok=True)

    malicious_records = get_malicious_records(dataset.records)
    blocklist_ips = collect_blocklist_ips(dataset.records)
    markdown_report = build_markdown_report(dataset.records, dataset.summary, blocklist_ips)

    malicious_records_path = output_dir / "malicious-records.json"
    blocklist_path = output_dir / "blocklist.txt"
    report_path = output_dir / "report.md"

    write_json_document(
        malicious_records_path,
        {
            "malicious_record_count": len(malicious_records),
            "records": malicious_records,
        },
    )
    blocklist_path.write_text("\n".join(blocklist_ips) + ("\n" if blocklist_ips else ""), encoding="utf-8")
    report_path.write_text(markdown_report, encoding="utf-8")

    return {
        "malicious_records": malicious_records_path,
        "blocklist": blocklist_path,
        "report": report_path,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate safe action outputs and a report from processed honeypot records."
    )
    parser.add_argument(
        "--records-file",
        type=Path,
        required=True,
        help="Path to the processed JSONL event records file.",
    )
    parser.add_argument(
        "--summary-file",
        type=Path,
        help="Optional path to the JSON summary file generated by the pipeline.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory where the report bundle should be written.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.records_file.exists():
        parser.error(f"Records file not found: {args.records_file}")

    outputs = export_report_bundle(args.records_file, args.summary_file, args.output_dir)
    print(json.dumps({key: str(value) for key, value in outputs.items()}, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
