from __future__ import annotations

import argparse
import json
from collections import Counter
from io import BytesIO
from pathlib import Path
from typing import Any

from flask import Flask, abort, jsonify, request, send_file
from flask_cors import CORS

from .dashboard_data import (
    DashboardDataset,
    filter_records,
    get_record_by_id,
    load_dataset,
    load_dataset_from_db,
)
from .database import Database
from .reporting import build_markdown_report, collect_blocklist_ips, get_malicious_records
from .settings import Settings


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


def create_app(
    records_path: Path,
    summary_path: Path | None = None,
    db_path: Path | None = None,
) -> Flask:
    app = Flask(__name__)
    CORS(app)
    app.config["RECORDS_PATH"] = records_path
    app.config["SUMMARY_PATH"] = summary_path
    app.config["DB_PATH"] = db_path

    def _has_db() -> bool:
        p = app.config.get("DB_PATH")
        return p is not None and Path(p).exists()

    def _get_db() -> Database:
        p = Path(app.config["DB_PATH"])
        db = Database(p)
        db.initialize()
        return db

    def get_dataset() -> DashboardDataset:
        if _has_db():
            db = _get_db()
            # For the full dataset load, use db-backed
            records, _ = db.query_events()
            summary = db.get_summary()
            db.close()
            return DashboardDataset(records=records, skipped_lines=0, summary=summary)

        dataset = load_dataset(
            records_path=Path(app.config["RECORDS_PATH"]),
            summary_path=Path(app.config["SUMMARY_PATH"]) if app.config["SUMMARY_PATH"] else None,
        )
        dataset.records = [_normalize_record(record) for record in dataset.records]
        return dataset

    # ── JSON API Endpoints ──────────────────────────────────────────────

    @app.route("/api/summary")
    def api_summary():
        if _has_db():
            db = _get_db()
            summary = db.get_summary()
            blocklist_count = summary.get("blocklist_count", 0)
            malicious_count = summary.get("malicious_event_count", 0)
            top_threats = db.get_top_threats(10)
            filter_options = db.get_filter_options()
            db.close()

            top_attack_category = "none"
            cats = summary.get("by_attack_category", {})
            if cats:
                top_attack_category = max(cats.items(), key=lambda x: x[1])[0]

            return jsonify({
                "total_events": summary["total_events"],
                "unique_source_ips": summary["unique_source_ips"],
                "malicious_event_count": malicious_count,
                "blocklist_count": blocklist_count,
                "skipped_lines": 0,
                "top_attack_category": top_attack_category,
                "by_attack_category": summary.get("by_attack_category", {}),
                "by_event_type": summary.get("by_event_type", {}),
                "by_protocol": summary.get("by_protocol", {}),
                "by_risk_level": summary.get("by_risk_level", {}),
            })

        # JSONL fallback
        dataset = get_dataset()
        malicious_records = get_malicious_records(dataset.records)
        blocklist_ips = collect_blocklist_ips(dataset.records)

        top_attack_category = "none"
        category_counts = dataset.summary.get("by_attack_category")
        if isinstance(category_counts, dict) and category_counts:
            top_attack_category = max(category_counts.items(), key=lambda item: item[1])[0]

        return jsonify({
            "total_events": dataset.summary.get("total_events", 0),
            "unique_source_ips": dataset.summary.get("unique_source_ips", 0),
            "malicious_event_count": len(malicious_records),
            "blocklist_count": len(blocklist_ips),
            "skipped_lines": dataset.skipped_lines,
            "top_attack_category": top_attack_category,
            "by_attack_category": dataset.summary.get("by_attack_category", {}),
            "by_event_type": dataset.summary.get("by_event_type", {}),
            "by_protocol": dataset.summary.get("by_protocol", {}),
            "by_risk_level": dataset.summary.get("by_risk_level", {}),
        })

    @app.route("/api/events")
    def api_events():
        source_ip = request.args.get("source_ip", "").strip() or None
        event_type = request.args.get("event_type", "").strip() or None
        attack_category = request.args.get("attack_category", "").strip() or None
        protocol = request.args.get("protocol", "").strip() or None
        malicious_only = request.args.get("malicious_only") == "1"

        if _has_db():
            db = _get_db()
            records, total = db.query_events(
                source_ip=source_ip,
                event_type=event_type,
                attack_category=attack_category,
                protocol=protocol,
                malicious_only=malicious_only,
            )
            filter_options = db.get_filter_options()
            db.close()
            return jsonify({
                "total": total,
                "records": records,
                "filter_options": filter_options,
            })

        # JSONL fallback
        dataset = get_dataset()
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
        if _has_db():
            db = _get_db()
            record = db.get_event_by_id(record_id)
            db.close()
            if record is None:
                abort(404)
            return jsonify(record)

        # JSONL fallback
        dataset = get_dataset()
        record = get_record_by_id(dataset.records, record_id)
        if record is None:
            abort(404)
        return jsonify(record)

    @app.route("/api/top-threats")
    def api_top_threats():
        if _has_db():
            db = _get_db()
            threats = db.get_top_threats(10)
            db.close()
            return jsonify({"threats": threats})

        # JSONL fallback
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

    # ── Attack Session Endpoints (database only) ───────────────────────

    @app.route("/api/sessions")
    def api_sessions():
        if not _has_db():
            return jsonify({"sessions": [], "total": 0, "message": "Database not configured"})

        source_ip = request.args.get("source_ip", "").strip() or None
        malicious_only = request.args.get("malicious_only") == "1"

        db = _get_db()
        sessions, total = db.query_attack_sessions(
            source_ip=source_ip,
            malicious_only=malicious_only,
        )
        db.close()
        return jsonify({"sessions": sessions, "total": total})

    @app.route("/api/sessions/<session_id>/timeline")
    def api_session_timeline(session_id: str):
        if not _has_db():
            return jsonify({"events": [], "message": "Database not configured"})

        source_ip = request.args.get("source_ip", "").strip()
        if not source_ip:
            return jsonify({"error": "source_ip query parameter is required"}), 400

        db = _get_db()
        events = db.get_session_timeline(session_id, source_ip)
        db.close()
        return jsonify({"events": events, "session_id": session_id, "source_ip": source_ip})

    # ── Export Endpoints ────────────────────────────────────────────────

    def get_filtered_records() -> list[dict[str, Any]]:
        source_ip = request.args.get("source_ip", "").strip() or None
        event_type = request.args.get("event_type", "").strip() or None
        attack_category = request.args.get("attack_category", "").strip() or None
        protocol = request.args.get("protocol", "").strip() or None
        malicious_only = request.args.get("malicious_only") == "1"

        if _has_db():
            db = _get_db()
            records, _ = db.query_events(
                source_ip=source_ip,
                event_type=event_type,
                attack_category=attack_category,
                protocol=protocol,
                malicious_only=malicious_only,
            )
            db.close()
            return records

        dataset = get_dataset()
        return filter_records(
            dataset.records,
            source_ip=source_ip,
            event_type=event_type,
            attack_category=attack_category,
            protocol=protocol,
            malicious_only=malicious_only,
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
        if _has_db():
            db = _get_db()
            summary = db.get_summary()
            db.close()
        else:
            dataset = get_dataset()
            summary = dataset.summary

        blocklist_ips = collect_blocklist_ips(records)
        report = build_markdown_report(records, summary, blocklist_ips)
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
        "--db",
        type=Path,
        help="Optional SQLite database path. If the file exists, the API reads from it.",
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

    settings = Settings.from_env()

    # Resolve database path
    db_path: Path | None = None
    if args.db:
        db_path = args.db
    else:
        db_url = settings.database_url
        if db_url and db_url != "data/honeypot.db" or Path(db_url).exists():
            db_path = Path(db_url)

    # Pre-initialize the database so the file exists
    if db_path is not None:
        db = Database(db_path)
        db.initialize()
        db.close()

    app = create_app(
        records_path=args.records_file,
        summary_path=args.summary_file,
        db_path=db_path,
    )
    app.run(host=args.host, port=args.port, debug=args.debug)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
