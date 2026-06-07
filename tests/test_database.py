from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from honeypot_pipeline.database import Database


class DatabaseEventTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmpdir.name) / "test.db"
        self.db = Database(self.db_path)
        self.db.initialize()

    def tearDown(self) -> None:
        self.db.close()
        self.tmpdir.cleanup()

    def _make_record(self, **overrides: object) -> dict:
        base = {
            "timestamp": "2026-03-18T12:00:00Z",
            "event_type": "cowrie.login.failed",
            "honeypot": "cowrie",
            "source_ip": "203.0.113.10",
            "source_port": 60222,
            "session_id": "abc123",
            "username": "root",
            "password": "toor",
            "protocol": "ssh",
            "classification": {"attack_category": "brute_force", "severity": "medium"},
            "threat_intel": {
                "status": "completed",
                "score": {"is_malicious": False, "confidence": "low"},
            },
            "raw_event": {"eventid": "cowrie.login.failed"},
        }
        base.update(overrides)  # type: ignore[arg-type]
        return base

    # ── Event inserts ─────────────────────────────────────────────────

    def test_insert_event_returns_id(self) -> None:
        event_id = self.db.insert_event(self._make_record())
        self.assertIsInstance(event_id, int)
        self.assertGreater(event_id, 0)

    def test_insert_event_stores_fields(self) -> None:
        self.db.insert_event(self._make_record())
        records, total = self.db.query_events()
        self.assertEqual(total, 1)
        r = records[0]
        self.assertEqual(r["source_ip"], "203.0.113.10")
        self.assertEqual(r["event_type"], "cowrie.login.failed")
        self.assertEqual(r["classification"]["attack_category"], "brute_force")
        self.assertIn("risk", r)

    def test_dedup_skips_duplicate_within_window(self) -> None:
        rec = self._make_record()
        first_id = self.db.insert_event(rec)
        second_id = self.db.insert_event(rec, dedup_window=99999)
        self.assertIsNotNone(first_id)
        self.assertIsNone(second_id)

    def test_dedup_allows_different_event_types(self) -> None:
        self.db.insert_event(self._make_record(event_type="cowrie.login.failed"))
        second = self.db.insert_event(self._make_record(event_type="cowrie.command.input"))
        self.assertIsNotNone(second)

    def test_dedup_allows_different_sessions(self) -> None:
        self.db.insert_event(self._make_record(session_id="abc123"))
        second = self.db.insert_event(self._make_record(session_id="xyz789"))
        self.assertIsNotNone(second)

    # ── Query events ──────────────────────────────────────────────────

    def test_query_events_by_source_ip(self) -> None:
        self.db.insert_event(self._make_record(source_ip="1.1.1.1"))
        self.db.insert_event(self._make_record(source_ip="2.2.2.2"))
        records, total = self.db.query_events(source_ip="1.1.1.1")
        self.assertEqual(total, 1)
        self.assertEqual(records[0]["source_ip"], "1.1.1.1")

    def test_query_events_by_attack_category(self) -> None:
        self.db.insert_event(
            self._make_record(classification={"attack_category": "malware_download", "severity": "high"})
        )
        self.db.insert_event(self._make_record())
        records, total = self.db.query_events(attack_category="malware_download")
        self.assertEqual(total, 1)

    def test_query_events_malicious_only(self) -> None:
        self.db.insert_event(self._make_record())
        self.db.insert_event(
            self._make_record(
                event_type="cowrie.command.input",
                session_id="xyz789",
                threat_intel={"status": "completed", "score": {"is_malicious": True, "confidence": "high"}}
            )
        )
        records, total = self.db.query_events(malicious_only=True)
        self.assertEqual(total, 1)
        self.assertEqual(records[0]["is_malicious"], 1)

    # ── Threat intel ──────────────────────────────────────────────────

    def test_insert_threat_intel(self) -> None:
        event_id = self.db.insert_event(self._make_record())
        ti_data = {
            "status": "completed",
            "lookup_ip": "203.0.113.10",
            "providers": {
                "abuseipdb": {
                    "status": "completed",
                    "is_malicious": True,
                    "result": {"abuse_confidence_score": 75},
                }
            },
            "score": {"is_malicious": True, "confidence": "medium"},
        }
        self.db.insert_threat_intel(event_id, ti_data)

        record = self.db.get_event_by_id(event_id)
        self.assertIsNotNone(record)
        self.assertTrue(record["threat_intel"]["score"]["is_malicious"])
        self.assertEqual(
            record["threat_intel"]["providers"]["abuseipdb"]["result"]["abuse_confidence_score"],
            75,
        )

    def test_get_event_by_id_with_threat_intel(self) -> None:
        event_id = self.db.insert_event(
            self._make_record(
                threat_intel={"status": "completed", "score": {"is_malicious": True}}
            )
        )
        ti_data = {
            "status": "completed",
            "lookup_ip": "203.0.113.10",
            "providers": {},
            "score": {"is_malicious": True, "confidence": "high"},
        }
        self.db.insert_threat_intel(event_id, ti_data)

        record = self.db.get_event_by_id(event_id)
        self.assertIsNotNone(record)
        self.assertEqual(record["threat_intel"]["score"]["confidence"], "high")

    # ── Attack sessions ───────────────────────────────────────────────

    def test_upsert_attack_session_creates_new(self) -> None:
        rec = self._make_record(session_id="sess1", source_ip="10.0.0.1")
        self.db.insert_event(rec)
        self.db.upsert_attack_session(rec)

        sessions, total = self.db.query_attack_sessions()
        self.assertEqual(total, 1)
        s = sessions[0]
        self.assertEqual(s["session_id"], "sess1")
        self.assertEqual(s["source_ip"], "10.0.0.1")
        self.assertEqual(s["event_count"], 1)
        self.assertIn("brute_force", s["attack_categories"])
        self.assertGreater(s["risk_score"], 0)
        self.assertIn("category:brute_force", s["risk_reasons"])

    def test_upsert_attack_session_updates_existing(self) -> None:
        rec1 = self._make_record(session_id="sess1", source_ip="10.0.0.1")
        rec2 = self._make_record(
            session_id="sess1",
            source_ip="10.0.0.1",
            event_type="cowrie.command.input",
            classification={"attack_category": "reconnaissance", "severity": "low"},
        )
        self.db.insert_event(rec1)
        self.db.upsert_attack_session(rec1)
        self.db.insert_event(rec2)
        self.db.upsert_attack_session(rec2)

        sessions, total = self.db.query_attack_sessions()
        self.assertEqual(total, 1)
        s = sessions[0]
        self.assertEqual(s["event_count"], 2)
        self.assertIn("brute_force", s["attack_categories"])
        self.assertIn("reconnaissance", s["attack_categories"])

    def test_upsert_attack_session_tracks_malicious(self) -> None:
        rec = self._make_record(
            session_id="sess1",
            source_ip="10.0.0.1",
            threat_intel={"status": "completed", "score": {"is_malicious": True}},
        )
        self.db.insert_event(rec)
        self.db.upsert_attack_session(rec)

        sessions, _ = self.db.query_attack_sessions(malicious_only=True)
        self.assertEqual(len(sessions), 1)

    def test_get_session_timeline(self) -> None:
        rec1 = self._make_record(
            session_id="sess1",
            source_ip="10.0.0.1",
            timestamp="2026-03-18T12:00:00Z",
            event_type="cowrie.login.failed",
        )
        rec2 = self._make_record(
            session_id="sess1",
            source_ip="10.0.0.1",
            timestamp="2026-03-18T12:05:00Z",
            event_type="cowrie.command.input",
        )
        self.db.insert_event(rec1)
        self.db.insert_event(rec2)

        events = self.db.get_session_timeline("sess1", "10.0.0.1")
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["event_type"], "cowrie.login.failed")
        self.assertEqual(events[1]["event_type"], "cowrie.command.input")

    # ── Summary ───────────────────────────────────────────────────────

    def test_get_summary(self) -> None:
        self.db.insert_event(self._make_record(source_ip="1.1.1.1"))
        self.db.insert_event(self._make_record(source_ip="2.2.2.2"))
        self.db.insert_event(
            self._make_record(
                source_ip="1.1.1.1",
                event_type="cowrie.command.input",
                classification={"attack_category": "malware_download", "severity": "high"},
                threat_intel={"status": "completed", "score": {"is_malicious": True}},
            )
        )

        summary = self.db.get_summary()
        self.assertEqual(summary["total_events"], 3)
        self.assertEqual(summary["unique_source_ips"], 2)
        self.assertEqual(summary["malicious_event_count"], 1)
        self.assertEqual(summary["by_attack_category"]["brute_force"], 2)
        self.assertEqual(summary["by_attack_category"]["malware_download"], 1)

    def test_get_top_threats(self) -> None:
        for i in range(5):
            self.db.insert_event(self._make_record(source_ip=f"10.0.0.{i}"))
        # IP 10.0.0.1 appears 3 times
        self.db.insert_event(self._make_record(source_ip="10.0.0.1", event_type="cowrie.command.input"))
        self.db.insert_event(self._make_record(source_ip="10.0.0.1", event_type="cowrie.session.connect"))

        threats = self.db.get_top_threats(3)
        self.assertEqual(len(threats), 3)
        self.assertEqual(threats[0]["ip"], "10.0.0.1")
        self.assertEqual(threats[0]["count"], 3)


if __name__ == "__main__":
    unittest.main()
