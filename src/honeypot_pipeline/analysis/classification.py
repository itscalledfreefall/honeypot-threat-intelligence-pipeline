from __future__ import annotations

from ..models import NormalizedEvent

_DOWNLOAD_MARKERS = (
    "wget ",
    "curl ",
    "tftp ",
    "ftpget ",
    "invoke-webrequest",
    "iwr ",
    "certutil ",
    "bitsadmin ",
)

_RECON_MARKERS = (
    "uname",
    "whoami",
    "id",
    "hostname",
    "ifconfig",
    "ip addr",
    "ip a",
    "netstat",
    "ss ",
    "ps ",
    "cat /etc/passwd",
)

_PERSISTENCE_MARKERS = (
    "chmod +x",
    "crontab",
    "authorized_keys",
    "systemctl enable",
    "nohup ",
    "/etc/rc.local",
)


def _contains_any(text: str, markers: tuple[str, ...]) -> bool:
    return any(marker in text for marker in markers)


def classify_event(event: NormalizedEvent) -> dict[str, str]:
    """Assign a simple deterministic category for downstream reporting."""

    command = (event.command or "").lower()
    event_type = event.event_type.lower()
    protocol = (event.protocol or "").lower() or "unknown"

    classification = {
        "target_profile": "server" if event.honeypot == "cowrie" else "unknown",
        "service_type": protocol,
        "attack_category": "unknown",
        "severity": "low",
        "reason": "No classification rule matched the event.",
    }

    if "login.failed" in event_type or "login.success" in event_type:
        classification["attack_category"] = "brute_force"
        classification["severity"] = "medium"
        classification["reason"] = "Authentication activity was observed on the honeypot."
        return classification

    if "file_download" in event_type or event.url or _contains_any(command, _DOWNLOAD_MARKERS):
        classification["attack_category"] = "malware_download"
        classification["severity"] = "high"
        classification["reason"] = "The event contains payload download behavior."
        return classification

    if _contains_any(command, _PERSISTENCE_MARKERS):
        classification["attack_category"] = "persistence"
        classification["severity"] = "high"
        classification["reason"] = "The command suggests an attempt to maintain access."
        return classification

    if _contains_any(command, _RECON_MARKERS):
        classification["attack_category"] = "reconnaissance"
        classification["severity"] = "low"
        classification["reason"] = "The command matches common host-enumeration behavior."
        return classification

    if command:
        classification["attack_category"] = "command_execution"
        classification["severity"] = "medium"
        classification["reason"] = "The attacker executed a command on the honeypot."

    return classification
