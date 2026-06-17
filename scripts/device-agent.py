#!/usr/bin/env python3
"""Lightweight honeypot device agent.

Collects basic host metrics using safe local reads (no shell commands, no
external data execution) and reports them to the dashboard heartbeat endpoint.

Usage:
    python3 device-agent.py --api-url http://dashboard:5000 --token <agent-token>
    python3 device-agent.py --api-url http://dashboard:5000 --token <token> --once

The agent token is issued once when a device is enrolled from the Devices tab.
It is not a user login token and only authorizes heartbeat updates.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import time
import urllib.request
from typing import Any

HEARTBEAT_INTERVAL_SECONDS = 30


def _read_uptime_seconds() -> int | None:
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as fh:
            return int(float(fh.read().split()[0]))
    except (OSError, ValueError, IndexError):
        return None


def _read_memory() -> dict[str, Any]:
    """Return RAM usage from /proc/meminfo (values in MB)."""
    try:
        info: dict[str, int] = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split(":")
                if len(parts) != 2:
                    continue
                key = parts[0].strip()
                value = parts[1].strip().split()[0]
                info[key] = int(value)  # kB
    except (OSError, ValueError, IndexError):
        return {}

    total_kb = info.get("MemTotal")
    available_kb = info.get("MemAvailable")
    if not total_kb or available_kb is None:
        return {}

    used_kb = total_kb - available_kb
    return {
        "ram_total_mb": total_kb // 1024,
        "ram_used_mb": used_kb // 1024,
        "ram_percent": round(used_kb / total_kb * 100, 1),
    }


def _read_load() -> dict[str, Any]:
    try:
        one, five, fifteen = os.getloadavg()
    except (OSError, AttributeError):
        return {}
    return {
        "load_1m": round(one, 2),
        "load_5m": round(five, 2),
        "load_15m": round(fifteen, 2),
        "cpu_count": os.cpu_count() or 0,
    }


def _read_disk() -> dict[str, Any]:
    try:
        usage = shutil.disk_usage("/")
    except OSError:
        return {}
    gb = 1024 ** 3
    return {
        "disk_total_gb": round(usage.total / gb, 1),
        "disk_used_gb": round(usage.used / gb, 1),
        "disk_percent": round(usage.used / usage.total * 100, 1) if usage.total else 0.0,
    }


def _local_ip() -> str | None:
    """Best-effort local IP without sending any traffic."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("10.255.255.255", 1))  # no packets sent for UDP connect
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def collect_metrics() -> dict[str, Any]:
    metrics: dict[str, Any] = {
        "hostname": socket.gethostname(),
        "service_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    uptime = _read_uptime_seconds()
    if uptime is not None:
        metrics["uptime_seconds"] = uptime
    ip = _local_ip()
    if ip:
        metrics["local_ip"] = ip
    metrics.update(_read_memory())
    metrics.update(_read_load())
    metrics.update(_read_disk())
    return metrics


def send_heartbeat(api_url: str, token: str, metrics: dict[str, Any]) -> bool:
    endpoint = api_url.rstrip("/") + "/api/devices/heartbeat"
    body = json.dumps({"metrics": metrics}).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as resp:
            return 200 <= resp.status < 300
    except Exception as exc:  # noqa: BLE001 - report and keep running
        print(f"heartbeat failed: {exc}")
        return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Honeypot device metrics agent.")
    parser.add_argument(
        "--api-url",
        default=os.environ.get("HONEYPOT_API_URL", ""),
        help="Dashboard base URL, e.g. http://dashboard:5000",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("HONEYPOT_DEVICE_TOKEN", ""),
        help="Agent token issued when the device was enrolled.",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=HEARTBEAT_INTERVAL_SECONDS,
        help="Seconds between heartbeats.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Send a single heartbeat and exit.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if not args.api_url or not args.token:
        print("error: --api-url and --token are required")
        return 2

    interval = max(args.interval, 5)
    if not args.once:
        print(
            f"Reporting to {args.api_url} every {interval}s. Press Ctrl-C to stop."
        )

    while True:
        metrics = collect_metrics()
        ok = send_heartbeat(args.api_url, args.token, metrics)
        if ok:
            stamp = time.strftime("%H:%M:%S")
            print(f"[{stamp}] heartbeat sent ({metrics.get('hostname', 'unknown')})")
        if args.once:
            return 0 if ok else 1
        try:
            time.sleep(interval)
        except KeyboardInterrupt:
            print("\nStopped.")
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
