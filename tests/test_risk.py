from __future__ import annotations

import unittest

from honeypot_pipeline.risk import score_event_record, score_session_snapshot


class RiskScoringTests(unittest.TestCase):
    # ── Legacy tests ────────────────────────────────────────────────

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

    # ── New category risk points ────────────────────────────────────

    def test_destructive_action_scores_high(self) -> None:
        risk = score_event_record(
            {
                "event_type": "cowrie.command.input",
                "classification": {
                    "attack_category": "destructive_action",
                    "severity": "high",
                },
                "indicators": {},
            }
        )
        self.assertEqual(risk["score"], 75)  # 45 + 30 = 75
        self.assertIn("category:destructive_action", risk["reasons"])

    def test_cryptomining_scores_high(self) -> None:
        risk = score_event_record(
            {
                "event_type": "cowrie.command.input",
                "classification": {
                    "attack_category": "cryptomining",
                    "severity": "high",
                },
                "indicators": {},
            }
        )
        self.assertEqual(risk["score"], 70)  # 40 + 30 = 70
        self.assertIn("category:cryptomining", risk["reasons"])

    def test_privilege_escalation_scores_medium_high(self) -> None:
        risk = score_event_record(
            {
                "event_type": "cowrie.command.input",
                "classification": {
                    "attack_category": "privilege_escalation",
                    "severity": "high",
                },
                "indicators": {},
            }
        )
        self.assertEqual(risk["score"], 65)  # 35 + 30 = 65
        self.assertIn("category:privilege_escalation", risk["reasons"])

    def test_defense_evasion_scores_medium_high(self) -> None:
        risk = score_event_record(
            {
                "event_type": "cowrie.command.input",
                "classification": {
                    "attack_category": "defense_evasion",
                    "severity": "high",
                },
                "indicators": {},
            }
        )
        self.assertEqual(risk["score"], 60)  # 30 + 30 = 60
        self.assertIn("category:defense_evasion", risk["reasons"])

    def test_credential_access_scores_medium(self) -> None:
        risk = score_event_record(
            {
                "event_type": "cowrie.command.input",
                "classification": {
                    "attack_category": "credential_access",
                    "severity": "medium",
                },
                "indicators": {},
            }
        )
        self.assertEqual(risk["score"], 40)  # 25 + 15 = 40
        self.assertIn("category:credential_access", risk["reasons"])

    def test_obfuscation_scores_low_medium(self) -> None:
        risk = score_event_record(
            {
                "event_type": "cowrie.command.input",
                "classification": {
                    "attack_category": "obfuscation",
                    "severity": "medium",
                },
                "indicators": {},
            }
        )
        self.assertEqual(risk["score"], 35)  # 20 + 15 = 35
        self.assertIn("category:obfuscation", risk["reasons"])

    # ── Session combo reasons ───────────────────────────────────────

    def test_recon_plus_privilege_escalation_combo(self) -> None:
        risk = score_session_snapshot(
            event_count=6,
            attack_categories=["reconnaissance", "privilege_escalation"],
            severity_counts={"low": 3, "high": 3},
            is_malicious=False,
        )
        self.assertIn("recon_plus_privilege_escalation", risk["reasons"])
        # event_count 6 → multi_event_session +5
        # categories: recon 10 + privesc 35 = 45
        # severity: 3 high → min(25, 30) = 25
        # combos: recon_plus_privilege_escalation +15
        # Total: 5 + 45 + 25 + 15 = 90 → critical
        self.assertGreaterEqual(risk["score"], 80)
        self.assertEqual(risk["level"], "critical")

    def test_download_plus_cryptomining_combo(self) -> None:
        risk = score_session_snapshot(
            event_count=10,
            attack_categories=["malware_download", "cryptomining"],
            severity_counts={"high": 4},
            is_malicious=True,
        )
        self.assertIn("download_plus_cryptomining", risk["reasons"])
        self.assertEqual(risk["level"], "critical")

    def test_credential_access_after_login_combo(self) -> None:
        risk = score_session_snapshot(
            event_count=5,
            attack_categories=["brute_force", "credential_access"],
            severity_counts={"medium": 5},
            is_malicious=False,
        )
        self.assertIn("credential_access_after_login", risk["reasons"])

    def test_evasion_plus_privilege_escalation_combo(self) -> None:
        risk = score_session_snapshot(
            event_count=8,
            attack_categories=["defense_evasion", "privilege_escalation"],
            severity_counts={"high": 4},
            is_malicious=False,
        )
        self.assertIn("evasion_plus_privilege_escalation", risk["reasons"])

    def test_obfuscated_download_combo(self) -> None:
        risk = score_session_snapshot(
            event_count=4,
            attack_categories=["obfuscation", "malware_download"],
            severity_counts={"medium": 2, "high": 2},
            is_malicious=False,
        )
        self.assertIn("obfuscated_download", risk["reasons"])

    def test_destructive_action_present_bonus(self) -> None:
        risk = score_session_snapshot(
            event_count=3,
            attack_categories=["destructive_action", "reconnaissance"],
            severity_counts={"high": 2, "low": 1},
            is_malicious=False,
        )
        self.assertIn("destructive_action_present", risk["reasons"])
        self.assertEqual(risk["level"], "critical")  # destructive is 45 + recon 10 + bonus 10 + severity 20 = 85

    # ── Full-chain session reaches high/critical ─────────────────────

    def test_full_chain_session_reaches_critical(self) -> None:
        risk = score_session_snapshot(
            event_count=30,
            attack_categories=[
                "brute_force",
                "reconnaissance",
                "credential_access",
                "privilege_escalation",
                "malware_download",
                "cryptomining",
                "persistence",
                "obfuscation",
                "defense_evasion",
                "destructive_action",
            ],
            severity_counts={"low": 5, "medium": 10, "high": 15},
            is_malicious=True,
        )
        self.assertEqual(risk["level"], "critical")
        self.assertEqual(risk["score"], 100)
        self.assertIn("recon_plus_privilege_escalation", risk["reasons"])
        self.assertIn("download_plus_cryptomining", risk["reasons"])
        self.assertIn("credential_access_after_login", risk["reasons"])
        self.assertIn("destructive_action_present", risk["reasons"])


    # ── DDoS risk scoring ─────────────────────────────────────────────

    def test_ddos_event_scores_high(self) -> None:
        risk = score_event_record(
            {
                "event_type": "cowrie.command.input",
                "classification": {
                    "attack_category": "ddos",
                    "severity": "high",
                },
                "indicators": {},
            }
        )
        self.assertEqual(risk["score"], 65)  # 35 + 30 = 65
        self.assertIn("category:ddos", risk["reasons"])

    def test_ddos_with_bruteforce_combo(self) -> None:
        risk = score_session_snapshot(
            event_count=50,
            attack_categories=["ddos", "brute_force"],
            severity_counts={"medium": 30, "high": 10},
            is_malicious=True,
        )
        self.assertIn("ddos_with_bruteforce", risk["reasons"])
        self.assertEqual(risk["level"], "critical")

    def test_ddos_botnet_persistence_combo(self) -> None:
        risk = score_session_snapshot(
            event_count=20,
            attack_categories=["ddos", "persistence"],
            severity_counts={"high": 5},
            is_malicious=False,
        )
        self.assertIn("ddos_botnet_persistence", risk["reasons"])


if __name__ == "__main__":
    unittest.main()
