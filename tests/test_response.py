from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from honeypot_pipeline.response import FirewallManager, _resolve_blocklist_ips


class FirewallManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mgr = FirewallManager(chain="INPUT", apply=False, comment_prefix="test-hp-block")

    # ── build_rules ────────────────────────────────────────────────────

    def test_build_rules_generates_iptables_commands(self) -> None:
        rules = self.mgr.build_rules(["10.0.0.1", "192.168.1.1"])
        self.assertEqual(len(rules), 2)
        for r in rules:
            self.assertIn("iptables -A INPUT", r["command"])
            self.assertIn("-j DROP", r["command"])
            self.assertIn("test-hp-block", r["command"])
        ips = {r["ip"] for r in rules}
        self.assertEqual(ips, {"10.0.0.1", "192.168.1.1"})

    def test_build_rules_skips_duplicate_ips(self) -> None:
        rules = self.mgr.build_rules(["10.0.0.1", "10.0.0.1", "10.0.0.2"])
        self.assertEqual(len(rules), 2)

    def test_build_rules_marks_existing_as_skipped(self) -> None:
        mgr = self.mgr
        with patch.object(mgr, "_list_blocked_ips", return_value={"10.0.0.1"}):
            rules = mgr.build_rules(["10.0.0.1", "10.0.0.2"])
        self.assertEqual(len(rules), 2)
        self.assertIn("skipped", rules[0]["command"])
        self.assertNotIn("skipped", rules[1]["command"])

    # ── block_ips (dry-run) ────────────────────────────────────────────

    def test_block_ips_dry_run_does_not_call_iptables(self) -> None:
        with patch.object(self.mgr, "_list_blocked_ips", return_value=set()):
            with patch.object(self.mgr, "_rule_exists", return_value=False):
                results = self.mgr.block_ips(["10.0.0.1"])
        self.assertEqual(len(results), 1)
        self.assertIn("iptables -A", results[0]["command"])

    def test_block_ips_apply_calls_iptables(self) -> None:
        mgr = FirewallManager(apply=True, comment_prefix="test-hp-block")
        with patch.object(mgr, "_rule_exists", return_value=False):
            with patch("subprocess.run") as mock_run:
                results = mgr.block_ips(["10.0.0.1"])
        # Should have called iptables -A
        self.assertTrue(any("APPLIED" in r["command"] for r in results))

    # ── unblock_ips ────────────────────────────────────────────────────

    def test_unblock_ips_dry_run(self) -> None:
        with patch.object(self.mgr, "_list_blocked_ips", return_value={"10.0.0.1"}):
            results = self.mgr.unblock_ips(["10.0.0.1", "10.0.0.99"])
        self.assertEqual(len(results), 2)
        self.assertIn("iptables -D", results[0]["command"])
        self.assertIn("skipped", results[1]["command"])

    # ── list_blocks ────────────────────────────────────────────────────

    def test_list_blocks_returns_sorted_ips(self) -> None:
        with patch.object(self.mgr, "_list_blocked_ips", return_value={"10.0.0.2", "10.0.0.1"}):
            blocked = self.mgr.list_blocks()
        self.assertEqual(blocked, ["10.0.0.1", "10.0.0.2"])

    def test_list_blocks_empty(self) -> None:
        with patch.object(self.mgr, "_list_blocked_ips", return_value=set()):
            blocked = self.mgr.list_blocks()
        self.assertEqual(blocked, [])

    # ── generate_script ────────────────────────────────────────────────

    def test_generate_script_produces_valid_shell(self) -> None:
        script = self.mgr.generate_script(["10.0.0.1"])
        self.assertIn("#!/usr/bin/env bash", script)
        self.assertIn("iptables -A", script)
        self.assertIn("10.0.0.1", script)
        self.assertIn("honeypot-block", script)

    def test_generate_script_all_already_blocked(self) -> None:
        with patch.object(self.mgr, "_list_blocked_ips", return_value={"10.0.0.1"}):
            script = self.mgr.generate_script(["10.0.0.1"])
        self.assertIn("Nothing to do", script)

    # ── _rule_exists ───────────────────────────────────────────────────

    def test_rule_exists_returns_true(self) -> None:
        mock = MagicMock()
        mock.return_value = 0
        with patch("subprocess.run", return_value=MagicMock(returncode=0)):
            self.assertTrue(self.mgr._rule_exists("10.0.0.1"))

    def test_rule_exists_returns_false(self) -> None:
        with patch("subprocess.run", side_effect=FileNotFoundError):
            self.assertFalse(self.mgr._rule_exists("10.0.0.1"))

    # ── _list_blocked_ips ──────────────────────────────────────────────

    def test_list_blocked_ips_parses_iptables_output(self) -> None:
        output = (
            "Chain INPUT (policy ACCEPT)\n"
            "num  target     prot opt source               destination\n"
            "1    DROP       all  --  10.0.0.1             0.0.0.0/0            /* test-hp-block */\n"
            "2    DROP       all  --  192.168.1.1          0.0.0.0/0            /* test-hp-block */\n"
            "3    ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0\n"
        )
        mock_result = MagicMock()
        mock_result.stdout = output
        with patch("subprocess.run", return_value=mock_result):
            ips = self.mgr._list_blocked_ips()
        self.assertEqual(ips, {"10.0.0.1", "192.168.1.1"})

    def test_list_blocked_ips_handles_missing_iptables(self) -> None:
        with patch("subprocess.run", side_effect=FileNotFoundError):
            ips = self.mgr._list_blocked_ips()
        self.assertEqual(ips, set())

    # ── _resolve_blocklist_ips ─────────────────────────────────────────

    def test_resolve_blocklist_from_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            records_path = Path(tmpdir) / "records.jsonl"
            records = [
                {
                    "source_ip": "10.0.0.99",
                    "threat_intel": {"score": {"is_malicious": True}},
                    "event_type": "test",
                }
            ]
            records_path.write_text(
                json.dumps(records[0]) + "\n", encoding="utf-8"
            )
            ips = _resolve_blocklist_ips(records_file=records_path)
            self.assertIn("10.0.0.99", ips)

    def test_resolve_blocklist_from_jsonl_includes_local_only_risk(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            records_path = Path(tmpdir) / "records.jsonl"
            record = {
                "source_ip": "10.0.0.42",
                "event_type": "cowrie.login.failed",
                "classification": {"attack_category": "brute_force", "severity": "medium"},
            }
            records_path.write_text(json.dumps(record) + "\n", encoding="utf-8")

            ips = _resolve_blocklist_ips(records_file=records_path)

        self.assertEqual(ips, ["10.0.0.42"])

    def test_resolve_blocklist_empty_when_no_sources(self) -> None:
        ips = _resolve_blocklist_ips()
        self.assertEqual(ips, [])


class ResponseCLITests(unittest.TestCase):
    """Minimal smoke tests for the CLI parser."""

    def test_parser_dry_run_is_default(self) -> None:
        from honeypot_pipeline.response import build_parser
        parser = build_parser()
        args = parser.parse_args(["--records-file", "/tmp/records.jsonl"])
        self.assertTrue(args.dry_run)
        self.assertFalse(args.apply)

    def test_parser_list_mode(self) -> None:
        from honeypot_pipeline.response import build_parser
        parser = build_parser()
        args = parser.parse_args(["--list"])
        self.assertTrue(args.list)

    def test_parser_ip_repeatable(self) -> None:
        from honeypot_pipeline.response import build_parser
        parser = build_parser()
        args = parser.parse_args(["--ip", "10.0.0.1", "--ip", "10.0.0.2"])
        self.assertEqual(args.ip, ["10.0.0.1", "10.0.0.2"])


if __name__ == "__main__":
    unittest.main()
