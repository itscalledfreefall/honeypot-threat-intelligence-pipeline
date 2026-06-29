#!/usr/bin/env python3
"""DDoS attack simulator — botnet flood against a honeypot server.

Simulates a distributed denial-of-service attack where multiple bot IPs
flood a target server with rapid SSH connections. Some bots also run
DDoS tools (hping3, slowloris, etc.) which trigger the ddos classification.

Three modes:
  --host <IP>     Live SSH flood from this machine against a real Cowrie
  --live          Generate offline botnet JSONL + auto-inject to Docker pipeline
  --output PATH   Generate offline botnet JSONL to file (inject manually)

Usage:
    # Live SSH flood — 20 bots x 10 connections against VM
    python3 scripts/ddos-attack.py --host 192.168.1.79 --bots 20 --connections 10

    # Offline + auto-inject to local Docker
    python3 scripts/ddos-attack.py --live --bots 50 --connections 15

    # Offline to file
    python3 scripts/ddos-attack.py --output /tmp/ddos.json --bots 50 --connections 15

All bot IPs use documentation-safe ranges (RFC 5737). Never connects to
real infrastructure in offline mode.
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
    "c2.example.com",
    "botnet.example.com",
    "stresser.example.com",
    "booter.example.net",
    "evil.example.com",
]

# Target IPs for the DDoS attack (what the bots are attacking)
_DDOS_TARGETS = [
    "203.0.113.50",
    "203.0.113.51",
    "203.0.113.99",
]

# ═══════════════════════════════════════════════════════════════════════
#  Bot credentials — random pairs for login flooding
# ═══════════════════════════════════════════════════════════════════════

_BOT_CREDS: list[tuple[str, str]] = [
    ("root", "root"), ("root", "admin"), ("root", "123456"),
    ("root", "password"), ("admin", "admin"), ("admin", "123456"),
    ("ubuntu", "ubuntu"), ("pi", "raspberry"), ("test", "test"),
    ("user", "123456"), ("oracle", "oracle"), ("guest", "guest"),
]

# ═══════════════════════════════════════════════════════════════════════
#  DDoS tool commands — triggers the ddos classification
# ═══════════════════════════════════════════════════════════════════════

_DDOS_TOOL_COMMANDS: list[str] = [
    "hping3 --flood -S -p 80 {target}",
    "hping3 --flood -S -p 443 {target}",
    "hping3 --flood --udp -p 53 {target}",
    "slowloris {target} 80",
    "goldeneye {target} 80",
    "pyloris {target} 80",
    "python3 synflood.py {target} 80",
    "python3 udpflood.py {target} 53",
    "python3 httpflood.py {target} 80",
    "perl flood.pl {target} 80",
    "nohup /tmp/ddos-agent --target {target} --port 80 --duration 600 &",
    "nohup /tmp/stresser --target {target} --port 443 &",
    "/tmp/botnet --connect {c2} --attack {target}",
    "hping --flood -S -p 80 {target}",
    "nping --flood --tcp -p 80 {target}",
    "python3 amp.py --type ntp amplify {target}",
    "python3 amp.py --type dns amplify {target}",
    "python3 amp.py --type ssdp amplify {target}",
    "memcached amplification {target} 11211",
]

# ═══════════════════════════════════════════════════════════════════════
#  Event helpers
# ═══════════════════════════════════════════════════════════════════════

def _safe_ip() -> str:
    return random.choice(_SAFE_IPS)


def _safe_domain() -> str:
    return random.choice(_SAFE_DOMAINS)


def _target() -> str:
    return random.choice(_DDOS_TARGETS)


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


# ═══════════════════════════════════════════════════════════════════════
#  Offline generator — multi-bot DDoS JSONL
# ═══════════════════════════════════════════════════════════════════════

def generate_ddos(
    output_path: str,
    bots: int,
    connections: int,
    include_tools: bool = True,
) -> int:
    """Generate Cowrie JSONL simulating a DDoS botnet flood.

    Each bot makes multiple rapid SSH connections (login failures) to the
    honeypot. Some bots also run DDoS tool commands. Returns total event count.
    """
    events: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    written = 0
    t = now

    # All bots attack in a tight 60-second window
    for b in range(bots):
        bot_ip = _safe_ip()
        c2 = _safe_domain()
        target = _target()
        sid = f"ddos-bot-{b:04d}"

        # Each bot makes `connections` rapid connection attempts
        for c in range(connections):
            user, pw = random.choice(_BOT_CREDS)

            # Session connect
            events.append(_event("cowrie.session.connect", sid, bot_ip, t,
                                 message=f"connection attempt {c+1}/{connections}"))
            written += 1
            t += timedelta(milliseconds=random.randint(100, 500))

            # Login failed (DDoS bots hammer credentials)
            events.append(_event("cowrie.login.failed", sid, bot_ip, t,
                                 username=user, password=pw,
                                 message=f"DDoS flood login attempt"))
            written += 1
            t += timedelta(milliseconds=random.randint(50, 300))

            # Session closed (rapid disconnect)
            events.append(_event("cowrie.session.closed", sid, bot_ip, t))
            written += 1
            t += timedelta(milliseconds=random.randint(50, 200))

        # 30% of bots also run DDoS tools (triggers ddos classification)
        if include_tools and random.random() < 0.3:
            # One successful login to run commands
            user, pw = random.choice(_BOT_CREDS)
            events.append(_event("cowrie.session.connect", sid, bot_ip, t))
            written += 1
            t += timedelta(milliseconds=200)

            events.append(_event("cowrie.login.success", sid, bot_ip, t,
                                 username=user, password=pw))
            written += 1
            t += timedelta(seconds=1)

            # Run 1-3 DDoS tool commands
            tool_count = random.randint(1, 3)
            chosen = random.sample(_DDOS_TOOL_COMMANDS, min(tool_count, len(_DDOS_TOOL_COMMANDS)))
            for cmd_template in chosen:
                cmd = cmd_template.format(target=target, c2=c2)
                events.append(_event("cowrie.command.input", sid, bot_ip, t,
                                     input=cmd))
                written += 1
                t += timedelta(seconds=random.randint(1, 3))

            events.append(_event("cowrie.session.closed", sid, bot_ip, t))
            written += 1

    # Write JSONL
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "a") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    return written


# ═══════════════════════════════════════════════════════════════════════
#  Live SSH flood — real connections against a Cowrie honeypot
# ═══════════════════════════════════════════════════════════════════════

def run_live_ddos_flood(
    host: str,
    port: int,
    bots: int,
    connections: int,
    connect_timeout: int = 5,
) -> int:
    """Flood a real Cowrie honeypot with rapid SSH connections.

    Uses sshpass for rapid non-interactive SSH. Each "bot" is a rapid burst
    of connection attempts. Cowrie logs every attempt.
    Returns number of successful connections made.
    """
    success = 0

    print(f"\n  DDoS FLOOD: {bots} bots x {connections} connections")
    print(f"  Target: {host}:{port}")
    print(f"  Total attempted connections: {bots * connections}")
    print(f"{'='*65}\n")

    for b in range(bots):
        user, pw = random.choice(_BOT_CREDS)
        bot_label = f"bot-{b:03d}"

        for c in range(connections):
            try:
                result = subprocess.run(
                    [
                        "sshpass", "-p", pw,
                        "ssh",
                        "-o", "StrictHostKeyChecking=no",
                        "-o", "UserKnownHostsFile=/dev/null",
                        "-o", f"ConnectTimeout={connect_timeout}",
                        "-p", str(port),
                        f"{user}@{host}",
                        "exit",
                    ],
                    capture_output=True,
                    timeout=connect_timeout + 3,
                )
                success += 1
            except subprocess.TimeoutExpired:
                pass  # Connection timeout is expected during flood
            except FileNotFoundError:
                print("  ✗ sshpass not found. Install: sudo apt-get install sshpass")
                return success
            except Exception:
                pass  # Connection refused, reset, etc. — all expected in flood

            # Very short delay between connections (DDoS = rapid)
            time.sleep(random.uniform(0.05, 0.2))

        if (b + 1) % 5 == 0 or b == bots - 1:
            print(f"  [{b+1}/{bots}] {bot_label}: {connections} connections sent")

        # Brief pause between bots
        if b < bots - 1:
            time.sleep(random.uniform(0.1, 0.5))

    print(f"\n  ✓ Flood complete: {success}/{bots * connections} connections landed")
    print(f"  → Dashboard: http://{host}:5173")
    print(f"  → Check /api/summary for spike\n")
    return success


# ═══════════════════════════════════════════════════════════════════════
#  Live injection into running pipeline (same pattern as honeypot-attack.py)
# ═══════════════════════════════════════════════════════════════════════

_COWRIE_LOG_FILE = "cowrie.json"


def _get_cowrie_volume_name() -> str | None:
    """Return the Docker volume name for the Cowrie logs, or None if not found."""
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
    """Append a Cowrie JSONL file into the running pipeline's log volume."""
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
        description="DDoS attack simulator — botnet flood against a honeypot server.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Live SSH flood against VM (real traffic)
    python3 scripts/ddos-attack.py --host 192.168.1.79 --bots 20 --connections 10

    # Offline + auto-inject to local Docker pipeline
    python3 scripts/ddos-attack.py --live --bots 50 --connections 15

    # Offline to file (inject manually later)
    python3 scripts/ddos-attack.py --output /tmp/ddos.json --bots 50 --connections 15

    # Disable DDoS tool commands (pure connection flood, no ddos category)
    python3 scripts/ddos-attack.py --live --bots 50 --connections 10 --no-tools
        """,
    )
    parser.add_argument(
        "--host", default=None, metavar="HOST",
        help="Live SSH flood: target this Cowrie honeypot IP with rapid connections.",
    )
    parser.add_argument(
        "--port", type=int, default=2222, metavar="PORT",
        help="SSH port for live flood (default: 2222)",
    )
    parser.add_argument(
        "--bots", type=int, default=20, metavar="N",
        help="Number of bot IPs in the DDoS botnet (default: 20)",
    )
    parser.add_argument(
        "--connections", type=int, default=10, metavar="N",
        help="SSH connections per bot (default: 10)",
    )
    parser.add_argument(
        "--live", action="store_true",
        help="Auto-inject generated events into the running Docker pipeline.",
    )
    parser.add_argument(
        "--output", default=None, metavar="PATH",
        help="Output Cowrie JSONL file (appends if exists).",
    )
    parser.add_argument(
        "--no-tools", action="store_true",
        help="Disable DDoS tool commands (pure connection flood, no ddos category).",
    )
    parser.add_argument(
        "--timeout", type=int, default=5, metavar="SEC",
        help="Connection timeout for live flood (default: 5s)",
    )
    args = parser.parse_args()

    if not args.host and not args.live and not args.output:
        parser.error("Provide --host, --live, or --output to specify the mode.")

    # ── Live SSH flood mode ──────────────────────────────────────────
    if args.host:
        print(f"\n{'='*65}")
        print(f"  DDoS ATTACK — LIVE SSH FLOOD")
        print(f"{'='*65}")
        run_live_ddos_flood(
            host=args.host,
            port=args.port,
            bots=args.bots,
            connections=args.connections,
            connect_timeout=args.timeout,
        )
        return 0

    # ── Offline generation (--live or --output) ─────────────────────
    if not args.output:
        if args.live:
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            args.output = f"/tmp/ddos-attack-{ts}.json"
        else:
            parser.error("--output is required (unless --host or --live)")

    print(f"\n{'='*65}")
    print(f"  DDoS ATTACK — BOTNET FLOOD GENERATOR")
    print(f"{'='*65}")
    print(f"  Output:       {args.output}")
    print(f"  Bots:         {args.bots}")
    print(f"  Connections:  {args.connections}/bot")
    print(f"  Total events: ~{args.bots * args.connections * 3} + DDoS tool commands")
    print(f"  DDoS tools:   {'disabled' if args.no_tools else 'enabled (30% of bots)'}")
    print(f"{'='*65}\n")

    written = generate_ddos(
        output_path=args.output,
        bots=args.bots,
        connections=args.connections,
        include_tools=not args.no_tools,
    )

    tool_label = "connection flood + DDoS tools" if not args.no_tools else "connection flood only"
    print(f"  ✓ {written} Cowrie JSON events written to {args.output}")
    print(f"  ✓ {args.bots} bots x {args.connections} connections ({tool_label})")

    if args.live:
        print()
        inject_to_live_pipeline(Path(args.output))
    else:
        print(f"\n  → Feed to dashboard:")
        print(f"    bash scripts/inject-cowrie-log.sh {args.output}")
        print(f"\n  → Or add --live to auto-inject into the running pipeline")
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
