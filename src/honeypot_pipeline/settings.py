from __future__ import annotations

import os
from dataclasses import dataclass


def _env_flag(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


@dataclass(slots=True)
class Settings:
    abuseipdb_api_key: str | None
    abuseipdb_base_url: str
    virustotal_api_key: str | None
    virustotal_base_url: str
    database_url: str
    blocklist_state_file: str
    firewall_chain: str
    firewall_comment_prefix: str
    firewall_host_namespace: bool

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY"),
            abuseipdb_base_url=os.getenv(
                "ABUSEIPDB_BASE_URL",
                "https://api.abuseipdb.com/api/v2/check",
            ),
            virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY"),
            virustotal_base_url=os.getenv(
                "VIRUSTOTAL_BASE_URL",
                "https://www.virustotal.com/api/v3/ip_addresses",
            ),
            database_url=os.getenv(
                "DATABASE_URL",
                "data/honeypot.db",
            ),
            blocklist_state_file=os.getenv(
                "BLOCKLIST_STATE_FILE",
                "/data/blocked-ips.json",
            ),
            firewall_chain=os.getenv(
                "FIREWALL_CHAIN",
                "INPUT",
            ),
            firewall_comment_prefix=os.getenv(
                "FIREWALL_COMMENT_PREFIX",
                "honeypot-block",
            ),
            firewall_host_namespace=_env_flag(
                "FIREWALL_HOST_NAMESPACE",
                True,
            ),
        )
