from __future__ import annotations

import unittest

from honeypot_pipeline.risk import score_event_record, score_session_snapshot


class RiskScoringTests(unittest.TestCase):
    def test_scores_payload_download_event_as_high_risk(self) -> None:
        record = {
            "event_type": "cowrie.command.input",
            "classification": {
                "attack_category": "malware_download",
                "severity": "high",
            },
            "indicators": {
                "urls": ["http://evil.example/dropper.sh"],
                "payload_references": ["http://evil.example/dropper.sh"],
                "hashes": [],
            },
            "threat_intel": {
                "score": {"is_malicious": True, "confidence": "high"},
            },
        }

        risk = score_event_record(record)

        self.assertEqual(risk["score"], 100)
        self.assertEqual(risk["level"], "critical")
        self.assertIn("category:malware_download", risk["reasons"])
        self.assertIn("malicious_ip:high", risk["reasons"])

    def test_scores_low_signal_event_as_minimal(self) -> None:
        risk = score_event_record(
            {
                "event_type": "cowrie.session.connect",
                "classification": {"attack_category": "unknown", "severity": "low"},
                "indicators": {},
            }
        )

        self.assertEqual(risk["level"], "minimal")

    def test_scores_session_from_aggregate_evidence(self) -> None:
        risk = score_session_snapshot(
            event_count=12,
            attack_categories=["brute_force", "malware_download", "persistence"],
            severity_counts={"medium": 4, "high": 2},
            is_malicious=True,
        )

        self.assertEqual(risk["score"], 100)
        self.assertEqual(risk["level"], "critical")
        self.assertIn("download_plus_persistence", risk["reasons"])


if __name__ == "__main__":
    unittest.main()

