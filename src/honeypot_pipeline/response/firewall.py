"""Automated incident response: firewall blocklist management.

Safe by default — all operations are dry-run unless ``apply=True`` is
explicitly passed.  Designed for lab environments where the pipeline
operator reviews blocklist candidates before enforcing them.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from ..api.dashboard_data import load_dataset
from ..reporting import collect_blocklist_ips
from ..settings import Settings
from ..storage.database import Database


class FirewallManager:
    """Manage iptables rules for honeypot blocklist enforcement.

    All mutating operations default to *dry_run=True*.  Pass
    ``apply=True`` only after reviewing the generated rules.
    """

    def __init__(
        self,
        chain: str = "INPUT",
        apply: bool = False,
        table: str = "filter",
        comment_prefix: str = "honeypot-block",
        command_prefix: list[str] | None = None,
        state_file: Path | None = None,
        wait_seconds: int = 5,
    ) -> None:
        self.chain = chain
        self.apply = apply
        self.table = table
        self.comment_prefix = comment_prefix
        self.command_prefix = list(command_prefix or [])
        self.state_file = state_file
        self.wait_seconds = max(0, wait_seconds)

    # ── Public API ──────────────────────────────────────────────────────

    def build_rules(self, ips: list[str]) -> list[dict[str, str]]:
        """Return the iptables commands that *would* be executed.

        Each result is a dict with ``ip`` and ``command`` keys.
        """
        rules: list[dict[str, str]] = []
        existing = self._list_blocked_ips()

        for ip in sorted(set(ips)):
            if ip in existing:
                rules.append({"ip": ip, "command": "# already blocked — skipped"})
                continue
            cmd = self._command_preview("A", ip)
            rules.append({"ip": ip, "command": cmd})

        return rules

    def block_ips(self, ips: list[str]) -> list[dict[str, str]]:
        """Generate and optionally apply iptables DROP rules for *ips*."""
        rules = self.build_rules(ips)

        if not self.apply:
            return rules

        applied: list[dict[str, str]] = []
        for rule in rules:
            if rule["command"].startswith("#"):
                applied.append(rule)
                continue

            ip = rule["ip"]
            if not self._rule_exists(ip):
                self._run_iptables(
                    ["-A", self.chain, "-s", ip, "-m", "comment", "--comment", self.comment_prefix, "-j", "DROP"],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                applied.append({"ip": ip, "command": f"{self._command_preview('A', ip)}  # APPLIED"})
            else:
                applied.append({"ip": ip, "command": "# already blocked — skipped"})

        return applied

    def unblock_ips(self, ips: list[str]) -> list[dict[str, str]]:
        """Remove iptables DROP rules for *ips*."""
        removed: list[dict[str, str]] = []
        existing = self._list_blocked_ips()

        for ip in sorted(set(ips)):
            if ip not in existing:
                removed.append({"ip": ip, "command": "# not blocked — skipped"})
                continue

            if self.apply:
                self._run_iptables(
                    ["-D", self.chain, "-s", ip, "-m", "comment", "--comment", self.comment_prefix, "-j", "DROP"],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                removed.append({"ip": ip, "command": f"{self._command_preview('D', ip)}  # REMOVED"})
            else:
                removed.append({
                    "ip": ip,
                    "command": self._command_preview("D", ip),
                })

        return removed

    def block_and_persist(self, ips: list[str]) -> list[dict[str, str]]:
        results = self.block_ips(ips)
        self._save_persisted_ips(self.list_blocks())
        return results

    def unblock_and_persist(self, ips: list[str]) -> list[dict[str, str]]:
        results = self.unblock_ips(ips)
        self._save_persisted_ips(self.list_blocks())
        return results

    def list_blocks(self) -> list[str]:
        """Return IPs currently blocked by this tool."""
        persisted = self._load_persisted_ips()
        actual = set(self._list_blocked_rule_stats())
        return sorted(actual | persisted)

    def list_block_statuses(self) -> dict[str, dict[str, int | bool]]:
        """Return blocked IPs with live firewall hit counters."""
        persisted = self._load_persisted_ips()
        actual = self._list_blocked_rule_stats()
        statuses: dict[str, dict[str, int | bool]] = {}

        for ip in sorted(set(actual) | persisted):
            stats = actual.get(ip, {})
            statuses[ip] = {
                "blocked": ip in actual or ip in persisted,
                "active": ip in actual,
                "packet_count": int(stats.get("packet_count", 0)),
                "byte_count": int(stats.get("byte_count", 0)),
            }

        return statuses

    def generate_script(self, ips: list[str]) -> str:
        """Build a standalone shell script that applies the blocklist."""
        rules = self.build_rules(ips)
        lines = [
            "#!/usr/bin/env bash",
            "# Auto-generated by honeypot-pipeline response module",
            "# Review before running: this script requires root.",
            "#",
            "# Dry-run: bash blocklist.sh --dry-run",
            "# Apply:    sudo bash blocklist.sh",
            "",
            "set -euo pipefail",
            "",
            'CHAIN="${CHAIN:-INPUT}"',
            "",
        ]

        if any(not r["command"].startswith("#") for r in rules):
            lines.append("echo 'Applying honeypot blocklist...'")
            for rule in rules:
                cmd = rule["command"]
                if cmd.startswith("#"):
                    lines.append(f"echo '{cmd}'")
                else:
                    ip = rule["ip"]
                    # Use iptables -C to check before -A
                    lines.append(
                        f"if ! {self._shell_iptables_command(['-C', '$CHAIN', '-s', ip, '-j', 'DROP'])} 2>/dev/null; then\n"
                        f"    {self._shell_iptables_command(['-A', '$CHAIN', '-s', ip, '-m', 'comment', '--comment', self.comment_prefix, '-j', 'DROP'])}\n"
                        f"    echo '  BLOCKED {ip}'\n"
                        f"else\n"
                        f"    echo '  SKIPPED {ip} (already blocked)'\n"
                        f"fi"
                    )
            lines.append("echo 'Done.'")
        else:
            lines.append("echo 'All IPs are already blocked. Nothing to do.'")

        return "\n".join(lines) + "\n"

    # ── Internal helpers ─────────────────────────────────────────────────

    def _iptables_command(self, args: list[str]) -> list[str]:
        wait_args = ["-w", str(self.wait_seconds)] if self.wait_seconds > 0 else []
        return [*self.command_prefix, "iptables", *wait_args, *args]

    def _shell_iptables_command(self, args: list[str]) -> str:
        return " ".join([*self.command_prefix, "iptables", *args])

    def _command_preview(self, action: str, ip: str) -> str:
        return self._shell_iptables_command(
            [f"-{action}", self.chain, "-s", ip, "-m", "comment", "--comment", f"\"{self.comment_prefix}\"", "-j", "DROP"]
        ).replace(" \"", " ").replace("\" ", " ")

    def _run_iptables(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
        return subprocess.run(self._iptables_command(args), **kwargs)

    def _load_persisted_ips(self) -> set[str]:
        if self.state_file is None or not self.state_file.exists():
            return set()
        try:
            payload = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return set()
        if not isinstance(payload, dict):
            return set()
        ips = payload.get("ips")
        if not isinstance(ips, list):
            return set()
        return {
            ip for ip in ips
            if isinstance(ip, str) and ip
        }

    def _save_persisted_ips(self, ips: list[str]) -> None:
        if self.state_file is None:
            return
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {"ips": sorted(set(ips))}
        self.state_file.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")

    def _rule_exists(self, ip: str) -> bool:
        """Check if a DROP rule for *ip* already exists in the chain."""
        try:
            result = self._run_iptables(
                [
                    "-C", self.chain,
                    "-s", ip,
                    "-m", "comment", "--comment", self.comment_prefix,
                    "-j", "DROP",
                ],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _list_blocked_ips(self) -> set[str]:
        """Parse iptables -L output for IPs blocked with our comment tag."""
        return set(self._list_blocked_rule_stats())

    def _list_blocked_rule_stats(self) -> dict[str, dict[str, int]]:
        """Parse verbose iptables output for blocked IPs and hit counters."""
        try:
            result = self._run_iptables(
                ["-L", self.chain, "-n", "-v", "--line-numbers"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return {}

        blocked: dict[str, dict[str, int]] = {}
        pattern = re.compile(
            rf"^\s*\d+\s+(\d+)\s+(\d+)\s+DROP\s+\S+\s+\S+\s+\S+\s+\S+\s+"
            rf"(\d{{1,3}}(?:\.\d{{1,3}}){{3}})\s+\S+.*{re.escape(self.comment_prefix)}"
        )
        for line in result.stdout.splitlines():
            match = pattern.match(line)
            if match is None:
                continue

            packet_count, byte_count, ip = match.groups()
            blocked[ip] = {
                "packet_count": int(packet_count),
                "byte_count": int(byte_count),
            }

        return blocked


# ── CLI helpers ────────────────────────────────────────────────────────────


def _resolve_blocklist_ips(
    records_file: Path | None = None,
    db_path: Path | None = None,
    malicious_only: bool = False,
) -> list[str]:
    """Collect blocklist IPs from JSONL records or database."""

    if db_path is not None and db_path.exists():
        db = Database(db_path)
        db.initialize()
        records, _ = db.query_events(malicious_only=malicious_only)
        db.close()
        return collect_blocklist_ips(records)

    if records_file is not None and records_file.exists():
        dataset = load_dataset(records_file)
        if malicious_only:
            from ..reporting import get_malicious_records
            records = get_malicious_records(dataset.records)
        else:
            records = dataset.records
        return collect_blocklist_ips(records)

    return []


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Apply or review iptables blocklist rules from pipeline output."
    )
    parser.add_argument(
        "--records-file",
        type=Path,
        help="Path to the processed JSONL event records file.",
    )
    parser.add_argument(
        "--db",
        type=Path,
        help="SQLite database path (reads blocklist from there if available).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Print rules without applying them (default).",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually apply iptables rules. Requires root. Bypasses --dry-run.",
    )
    parser.add_argument(
        "--unblock",
        action="store_true",
        help="Remove previously applied blocklist rules instead of adding them.",
    )
    parser.add_argument(
        "--chain",
        default="INPUT",
        help="iptables chain to target (default: INPUT).",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List currently blocked IPs and exit.",
    )
    parser.add_argument(
        "--generate-script",
        type=Path,
        help="Write a standalone shell script to this path instead of taking action.",
    )
    parser.add_argument(
        "--ip",
        action="append",
        help="Block a specific IP directly (repeatable). Overrides file/db sources.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    settings = Settings.from_env()

    mgr = FirewallManager(
        chain=args.chain or settings.firewall_chain,
        apply=args.apply,
        comment_prefix=settings.firewall_comment_prefix,
        command_prefix=["nsenter", "-t", "1", "-n"] if settings.firewall_host_namespace else [],
        state_file=Path(settings.blocklist_state_file),
    )

    # --list mode
    if args.list:
        blocked = mgr.list_blocks()
        if blocked:
            for ip in blocked:
                print(ip)
        else:
            print("# No honeypot-block rules found.")
        return 0

    # Resolve IPs
    if args.ip:
        ips = list(args.ip)
    else:
        db_path = args.db or (Path(settings.database_url) if Path(settings.database_url).exists() else None)
        ips = _resolve_blocklist_ips(
            records_file=args.records_file,
            db_path=db_path,
        )

    if not ips:
        print("No IPs to block. Run the pipeline first to populate the blocklist.")
        return 0

    # --generate-script mode
    if args.generate_script:
        script = mgr.generate_script(ips)
        args.generate_script.write_text(script, encoding="utf-8")
        args.generate_script.chmod(0o755)
        print(f"Script written to {args.generate_script}")
        print(f"  Review it, then run: sudo bash {args.generate_script}")
        return 0

    # --unblock mode
    if args.unblock:
        results = mgr.unblock_and_persist(ips) if args.apply else mgr.unblock_ips(ips)
        for r in results:
            print(r["command"])
        return 0

    # Default: block
    results = mgr.block_and_persist(ips) if args.apply else mgr.block_ips(ips)

    if args.apply:
        applied_count = sum(1 for r in results if "APPLIED" in r["command"])
        skipped_count = sum(1 for r in results if "skipped" in r["command"])
        print(f"Blocked {applied_count} IPs ({skipped_count} already blocked).")
    else:
        print("# DRY RUN — no rules applied. Use --apply to enforce.\n")
        for r in results:
            print(r["command"])
        print(f"\n# {len(ips)} IP(s) would be blocked.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
