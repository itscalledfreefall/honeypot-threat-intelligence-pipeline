from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest

# Import simulator module by file path (filename has a hyphen)
_sim_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts", "attack-simulator.py"))
_sim_spec = importlib.util.spec_from_file_location("attack_simulator", _sim_path)
_sim = importlib.util.module_from_spec(_sim_spec)
_sim_spec.loader.exec_module(_sim)

SCENARIO_PLAYBOOKS = _sim.SCENARIO_PLAYBOOKS  # type: ignore[reportUnknownVariableType]
generate_offline_scenario = _sim.generate_offline_scenario  # type: ignore[reportUnknownVariableType]


class SimulatorScenarioTests(unittest.TestCase):
    """Tests for attack-simulator scenario routing and offline generation."""

    def test_all_named_scenarios_registered(self) -> None:
        """Every scenario from the plan is registered in SCENARIO_PLAYBOOKS."""
        expected = {
            "brute-force", "recon", "payload-download", "persistence",
            "privilege-escalation", "credential-access", "cryptomining",
            "obfuscation", "defense-evasion", "destructive-action",
        }
        registered = set(SCENARIO_PLAYBOOKS.keys())
        missing = expected - registered
        self.assertEqual(missing, set(), f"Missing scenarios: {missing}")

    def test_no_playbook_has_unsafe_ips(self) -> None:
        """All playbook commands must use documentation-safe domains and IPs."""
        for scenario_name, playbook in SCENARIO_PLAYBOOKS.items():
            for cmd_template, _, _ in playbook:
                # After formatting, should not contain real-looking IPs
                filled = cmd_template.format(ip="192.0.2.1", domain="example.com")
                self.assertNotIn("103.45.67.89", filled,
                                 f"Unsafe IP in {scenario_name}: {cmd_template}")
                self.assertNotIn("185.220.101.34", filled,
                                 f"Unsafe IP in {scenario_name}: {cmd_template}")
                self.assertNotIn("evil-c2.malware.net", filled,
                                 f"Unsafe domain in {scenario_name}: {cmd_template}")
                self.assertNotIn("botnet-master.xyz", filled,
                                 f"Unsafe domain in {scenario_name}: {cmd_template}")

    def test_playbooks_are_non_empty(self) -> None:
        """Every non-brute scenario must have at least one command."""
        for scenario_name, playbook in SCENARIO_PLAYBOOKS.items():
            if scenario_name == "brute-force":
                continue
            self.assertGreater(len(playbook), 0,
                               f"Scenario {scenario_name} has no commands")


class OfflineGenerationTests(unittest.TestCase):
    """Tests for offline Cowrie JSON generation."""

    REQUIRED_EVENT_KEYS = {"eventid", "timestamp", "src_ip", "session", "protocol"}

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _generate_and_read(self, scenario: str, count: int = 1) -> list[dict]:
        """Generate offline events and return parsed JSON objects."""
        output_path = os.path.join(self.tmpdir, f"{scenario}.json")
        written = generate_offline_scenario(
            scenario=scenario,
            output_path=output_path,
            count=count,
            source_ip="198.51.100.42",
            session_prefix="test",
        )
        self.assertGreater(written, 0, f"No events generated for {scenario}")
        with open(output_path) as f:
            return [json.loads(line) for line in f if line.strip()]

    def test_offline_generates_valid_json_lines(self) -> None:
        events = self._generate_and_read("recon")
        for event in events:
            self.assertIsInstance(event, dict)

    def test_events_have_required_cowrie_fields(self) -> None:
        events = self._generate_and_read("recon")
        for event in events:
            for key in self.REQUIRED_EVENT_KEYS:
                self.assertIn(key, event, f"Missing key '{key}' in event: {event}")

    def test_generated_events_include_session_connect(self) -> None:
        events = self._generate_and_read("recon")
        eventids = {e["eventid"] for e in events}
        self.assertIn("cowrie.session.connect", eventids)

    def test_generated_events_include_session_closed(self) -> None:
        events = self._generate_and_read("recon")
        eventids = {e["eventid"] for e in events}
        self.assertIn("cowrie.session.closed", eventids)

    def test_generated_events_include_login_attempts(self) -> None:
        events = self._generate_and_read("recon")
        eventids = {e["eventid"] for e in events}
        self.assertIn("cowrie.login.success", eventids)
        # May or may not have login.failed depending on random — at minimum success

    def test_generated_events_include_command_input(self) -> None:
        events = self._generate_and_read("recon")
        eventids = {e["eventid"] for e in events}
        self.assertIn("cowrie.command.input", eventids)

    def test_command_events_have_input_field(self) -> None:
        events = self._generate_and_read("recon")
        cmd_events = [e for e in events if e["eventid"] == "cowrie.command.input"]
        self.assertGreater(len(cmd_events), 0)
        for ev in cmd_events:
            self.assertIn("input", ev)
            self.assertIsInstance(ev["input"], str)
            self.assertGreater(len(ev["input"]), 0)

    def test_source_ip_respected_in_offline_mode(self) -> None:
        events = self._generate_and_read("recon")
        for event in events:
            self.assertEqual(event["src_ip"], "198.51.100.42")

    def test_session_prefix_respected(self) -> None:
        events = self._generate_and_read("recon")
        for event in events:
            self.assertTrue(event["session"].startswith("test-"),
                            f"Session ID '{event['session']}' doesn't start with 'test-'")

    def test_count_generates_multiple_sessions(self) -> None:
        events = self._generate_and_read("recon", count=3)
        sessions = {e["session"] for e in events}
        self.assertEqual(len(sessions), 3)

    def test_deterministic_with_fixed_ip_and_prefix(self) -> None:
        """Same inputs produce valid Cowrie JSON (login attempt count may vary)."""
        path1 = os.path.join(self.tmpdir, "det1.json")
        path2 = os.path.join(self.tmpdir, "det2.json")
        generate_offline_scenario("recon", path1, count=1, source_ip="198.51.100.1", session_prefix="det")
        generate_offline_scenario("recon", path2, count=1, source_ip="198.51.100.1", session_prefix="det")
        with open(path1) as f1, open(path2) as f2:
            events1 = [json.loads(line) for line in f1 if line.strip()]
            events2 = [json.loads(line) for line in f2 if line.strip()]
        # Both must have connect, command.input, and closed
        self.assertGreater(len(events1), 3)
        self.assertGreater(len(events2), 3)
        ids1 = {e["eventid"] for e in events1}
        ids2 = {e["eventid"] for e in events2}
        self.assertEqual(ids1, ids2)

    # ── Per-scenario smoke tests ─────────────────────────────────────

    def test_each_scenario_generates_command_events(self) -> None:
        for scenario_name in SCENARIO_PLAYBOOKS:
            if scenario_name == "brute-force":
                continue
            with self.subTest(scenario=scenario_name):
                events = self._generate_and_read(scenario_name)
                cmd_events = [e for e in events if e["eventid"] == "cowrie.command.input"]
                self.assertGreater(
                    len(cmd_events), 0,
                    f"Scenario '{scenario_name}' generated no command.input events"
                )

    def test_full_chain_generates_all_event_types(self) -> None:
        events = self._generate_and_read("full-chain", count=1)
        eventids = {e["eventid"] for e in events}
        expected_types = {
            "cowrie.session.connect",
            "cowrie.login.failed",
            "cowrie.login.success",
            "cowrie.command.input",
            "cowrie.session.closed",
        }
        missing = expected_types - eventids
        self.assertEqual(missing, set(), f"Full-chain missing event types: {missing}")

    def test_full_chain_has_many_commands(self) -> None:
        events = self._generate_and_read("full-chain", count=1)
        cmd_events = [e for e in events if e["eventid"] == "cowrie.command.input"]
        self.assertGreater(len(cmd_events), 8, "Full-chain should have many commands across stages")

    def test_events_use_safe_domains_only(self) -> None:
        """Verify generated events don't contain real malicious domains."""
        events = self._generate_and_read("full-chain", count=2)
        for event in events:
            text = json.dumps(event)
            self.assertNotIn("evil-c2.malware.net", text)
            self.assertNotIn("botnet-master.xyz", text)
            self.assertNotIn("103.45.67.89", text)
            self.assertNotIn("185.220.101.34", text)


if __name__ == "__main__":
    unittest.main()
