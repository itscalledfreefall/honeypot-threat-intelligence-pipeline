from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(slots=True)
class Settings:
    abuseipdb_api_key: str | None
    abuseipdb_base_url: str

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY"),
            abuseipdb_base_url=os.getenv(
                "ABUSEIPDB_BASE_URL",
                "https://api.abuseipdb.com/api/v2/check",
            ),
        )

