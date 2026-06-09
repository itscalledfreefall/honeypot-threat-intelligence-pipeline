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

_PRIVESC_MARKERS = (
    "sudo -l",
    "find / -perm -4000",
    "/etc/sudoers",
    "getcap",
    "chmod u+s",
    "pkexec",
)

_CREDENTIAL_ACCESS_MARKERS = (
    "/etc/shadow",
    "id_rsa",
    ".bash_history",
    "grep -r password",
    "find / -name *.key",
    "~/.aws/credentials",
    "cat ~/.ssh/",
    "ls -la ~/.ssh",
    ".dockercfg",
    "wp-config.php",
    "credentials",
)

_CRYPTOMINING_MARKERS = (
    "xmrig",
    "stratum+tcp",
    "--pool",
    "--wallet",
    "minergate",
    "cpuminer",
    "minerd",
    "ccminer",
    "ethminer",
    "t-rex",
    "phoenixminer",
    "lolminer",
    "nbminer",
    "gminer",
    "--algo ",
    "cryptonight",
    "randomx",
)

_OBFUSCATION_MARKERS = (
    "base64 -d",
    "base64 --decode",
    "| base64",
    "eval ",
    "sh -c",
    "| sh",
    "| bash",
    "/dev/tcp/",
)

_DEFENSE_EVASION_MARKERS = (
    "rm -rf /var/log",
    "> /var/log/",
    "> .bash_history",
    "cat /dev/null >",
    "history -c",
    "unset histfile",
    "set +o history",
    "unset history",
    "rm -rf /tmp/.",
    "truncate -s 0",
    "systemctl stop",
    "service stop",
    "ufw disable",
)

_DESTRUCTIVE_MARKERS = (
    "rm -rf / ",
    "rm -rf /*",
    "rm -rf ~/",
    "rm -rf /tmp",
    "rm -rf /var",
    "rm -rf /etc",
    "rm -rf /home",
    "rm -rf /root",
    "mkfs.",
    ":(){ :|:& };:",
    "dd if=/dev/zero",
    "dd if=/dev/urandom",
    "> /dev/sd",
    "/dev/null of=/dev/",
    "mv /bin/",
    "mv /sbin/",
    "fdisk /dev/",
)


_SESSION_EVENT_MARKERS = (
    "session.closed",
    "session.params",
    "log.closed",
    "log.open",
    "client.",
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

    # ── New high-confidence specific categories (before generic fallback) ────

    if _contains_any(command, _DESTRUCTIVE_MARKERS):
        classification["attack_category"] = "destructive_action"
        classification["severity"] = "high"
        classification["reason"] = "The command indicates destructive or wiper-like intent."
        return classification

    if _contains_any(command, _CRYPTOMINING_MARKERS):
        classification["attack_category"] = "cryptomining"
        classification["severity"] = "high"
        classification["reason"] = "The command references cryptomining tools or pool connections."
        return classification

    if _contains_any(command, _DEFENSE_EVASION_MARKERS):
        classification["attack_category"] = "defense_evasion"
        classification["severity"] = "high"
        classification["reason"] = "The command appears to clear logs or disable defenses."
        return classification

    if _contains_any(command, _PRIVESC_MARKERS):
        classification["attack_category"] = "privilege_escalation"
        classification["severity"] = "high"
        classification["reason"] = "The command attempts to elevate privileges or enumerate escalation paths."
        return classification

    if _contains_any(command, _CREDENTIAL_ACCESS_MARKERS):
        classification["attack_category"] = "credential_access"
        classification["severity"] = "medium"
        classification["reason"] = "The command targets credential files, keys, or sensitive configuration."
        return classification

    if _contains_any(command, _RECON_MARKERS):
        classification["attack_category"] = "reconnaissance"
        classification["severity"] = "low"
        classification["reason"] = "The command matches common host-enumeration behavior."
        return classification

    if _contains_any(command, _OBFUSCATION_MARKERS):
        classification["attack_category"] = "obfuscation"
        classification["severity"] = "medium"
        classification["reason"] = "The command uses obfuscation techniques such as base64 decoding or eval."
        return classification

    if command:
        classification["attack_category"] = "command_execution"
        classification["severity"] = "medium"
        classification["reason"] = "The attacker executed a command on the honeypot."
        return classification

    # ── Session / connection lifecycle events (no attacker command) ──────────

    if "direct-tcpip" in event_type:
        classification["attack_category"] = "connection"
        classification["severity"] = "medium"
        classification["reason"] = "The client requested a forwarded TCP/IP channel, indicating tunneling or pivot attempts."
        return classification

    if "session.connect" in event_type:
        classification["attack_category"] = "connection"
        classification["severity"] = "low"
        classification["reason"] = "A new session was established with the honeypot."
        return classification

    if _contains_any(event_type, _SESSION_EVENT_MARKERS):
        classification["attack_category"] = "session"
        classification["severity"] = "low"
        classification["reason"] = "Session lifecycle or client metadata reported by the honeypot."
        return classification

    return classification
