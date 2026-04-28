from __future__ import annotations

import argparse
import json
from collections import Counter
from io import BytesIO
from pathlib import Path
from typing import Any

from flask import Flask, abort, jsonify, request, send_file
from flask_cors import CORS

from .dashboard_data import filter_records, get_record_by_id, load_dataset
from .reporting import build_markdown_report, collect_blocklist_ips, get_malicious_records


def _normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(record)
    command = normalized.get("command")
    if isinstance(command, str) and command:
        preview = command
    else:
        url = normalized.get("url")
        preview = url if isinstance(url, str) else ""
    if len(preview) > 90:
        preview = preview[:87] + "..."
    normalized["command_preview"] = preview
    return normalized


def _sorted_options(records: list[dict[str, Any]], key: str) -> list[str]:
    values = {record.get(key) for record in records if isinstance(record.get(key), str) and record.get(key)}
    return sorted(values)


def _sorted_category_options(records: list[dict[str, Any]]) -> list[str]:
    values = set()
    for record in records:
        classification = record.get("classification")
        if isinstance(classification, dict):
            category = classification.get("attack_category")
            if isinstance(category, str) and category:
                values.add(category)
    return sorted(values)


def create_app(records_path: Path, summary_path: Path | None = None) -> Flask:
    app = Flask(__name__)
    CORS(app)
    app.config["RECORDS_PATH"] = records_path
    app.config["SUMMARY_PATH"] = summary_path

    def get_dataset():
        dataset = load_dataset(
            records_path=Path(app.config["RECORDS_PATH"]),
            summary_path=Path(app.config["SUMMARY_PATH"]) if app.config["SUMMARY_PATH"] else None,
        )
        dataset.records = [_normalize_record(record) for record in dataset.records]
        return dataset

    # ── JSON API Endpoints ──────────────────────────────────────────────

    @app.route("/api/summary")
    def api_summary():
        dataset = get_dataset()
        summary = dataset.summary
        malicious_records = get_malicious_records(dataset.records)
        blocklist_ips = collect_blocklist_ips(dataset.records)

        top_attack_category = "none"
        category_counts = summary.get("by_attack_category")
        if isinstance(category_counts, dict) and category_counts:
            top_attack_category = max(category_counts.items(), key=lambda item: item[1])[0]

        return jsonify({
            "total_events": summary.get("total_events", 0),
            "unique_source_ips": summary.get("unique_source_ips", 0),
            "malicious_event_count": len(malicious_records),
            "blocklist_count": len(blocklist_ips),
            "skipped_lines": dataset.skipped_lines,
            "top_attack_category": top_attack_category,
            "by_attack_category": summary.get("by_attack_category", {}),
            "by_event_type": summary.get("by_event_type", {}),
            "by_protocol": summary.get("by_protocol", {}),
        })

    @app.route("/api/events")
    def api_events():
        dataset = get_dataset()
        source_ip = request.args.get("source_ip", "").strip() or None
        event_type = request.args.get("event_type", "").strip() or None
        attack_category = request.args.get("attack_category", "").strip() or None
        protocol = request.args.get("protocol", "").strip() or None
        malicious_only = request.args.get("malicious_only") == "1"

        records = filter_records(
            dataset.records,
            source_ip=source_ip,
            event_type=event_type,
            attack_category=attack_category,
            protocol=protocol,
            malicious_only=malicious_only,
        )

        return jsonify({
            "total": len(records),
            "records": records,
            "filter_options": {
                "event_types": _sorted_options(dataset.records, "event_type"),
                "attack_categories": _sorted_category_options(dataset.records),
                "protocols": _sorted_options(dataset.records, "protocol"),
            },
        })

    @app.route("/api/events/<int:record_id>")
    def api_event_detail(record_id: int):
        dataset = get_dataset()
        record = get_record_by_id(dataset.records, record_id)
        if record is None:
            abort(404)
        return jsonify(record)

    @app.route("/api/top-threats")
    def api_top_threats():
        dataset = get_dataset()
        ip_counter: Counter[str] = Counter()
        for record in dataset.records:
            ip = record.get("source_ip")
            if isinstance(ip, str) and ip:
                ip_counter[ip] += 1

        top = [
            {"ip": ip, "count": count}
            for ip, count in ip_counter.most_common(10)
        ]
        return jsonify({"threats": top})

    # ── Export Endpoints ────────────────────────────────────────────────

    def get_filtered_records() -> list[dict[str, Any]]:
        dataset = get_dataset()
        return filter_records(
            dataset.records,
            source_ip=request.args.get("source_ip", "").strip() or None,
            event_type=request.args.get("event_type", "").strip() or None,
            attack_category=request.args.get("attack_category", "").strip() or None,
            protocol=request.args.get("protocol", "").strip() or None,
            malicious_only=request.args.get("malicious_only") == "1",
        )

    @app.route("/api/exports/blocklist.txt")
    def export_blocklist():
        records = get_filtered_records()
        blocklist_ips = collect_blocklist_ips(records)
        payload = "\n".join(blocklist_ips) + ("\n" if blocklist_ips else "")
        return send_file(
            BytesIO(payload.encode("utf-8")),
            mimetype="text/plain; charset=utf-8",
            as_attachment=True,
            download_name="blocklist.txt",
        )

    @app.route("/api/exports/malicious.json")
    def export_malicious_json():
        records = get_filtered_records()
        malicious_records = get_malicious_records(records)
        payload = json.dumps(
            {
                "malicious_record_count": len(malicious_records),
                "records": malicious_records,
            },
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        return send_file(
            BytesIO(payload.encode("utf-8")),
            mimetype="application/json",
            as_attachment=True,
            download_name="malicious-records.json",
        )

    @app.route("/api/exports/report.md")
    def export_report_markdown():
        records = get_filtered_records()
        dataset = get_dataset()
        blocklist_ips = collect_blocklist_ips(records)
        report = build_markdown_report(records, dataset.summary, blocklist_ips)
        return send_file(
            BytesIO(report.encode("utf-8")),
            mimetype="text/markdown; charset=utf-8",
            as_attachment=True,
            download_name="honeypot-report.md",
        )

    return app


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the JSON API backend for the Sharingan dashboard."
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
        "--host",
        default="0.0.0.0",
        help="Host interface to bind the API server to.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Port to bind the API server to.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable Flask debug mode.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.records_file.exists():
        args.records_file.parent.mkdir(parents=True, exist_ok=True)
        args.records_file.touch()

    app = create_app(records_path=args.records_file, summary_path=args.summary_file)
    app.run(host=args.host, port=args.port, debug=args.debug)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
