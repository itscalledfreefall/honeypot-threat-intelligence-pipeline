from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(slots=True)
class Settings:
    abuseipdb_api_key: str | None
    abuseipdb_base_url: str
    virustotal_api_key: str | None
    virustotal_base_url: str
    database_url: str

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
        )
