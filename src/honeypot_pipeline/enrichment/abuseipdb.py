from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Callable
from urllib.parse import urlencode
from urllib.request import Request, urlopen


@dataclass(slots=True)
class AbuseIPDBResult:
    ip_address: str
    abuse_confidence_score: int | None
    country_code: str | None
    usage_type: str | None
    isp: str | None
    domain: str | None
    total_reports: int | None
    last_reported_at: str | None
    is_public: bool | None
    is_whitelisted: bool | None
    raw_response: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AbuseIPDBClient:
    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.abuseipdb.com/api/v2/check",
        timeout: float = 10.0,
        opener: Callable[..., Any] | None = None,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url
        self.timeout = timeout
        self._opener = opener or urlopen

    def lookup_ip(self, ip_address: str, max_age_in_days: int = 90) -> AbuseIPDBResult:
        query = urlencode(
            {
                "ipAddress": ip_address,
                "maxAgeInDays": max_age_in_days,
            }
        )
        request = Request(
            f"{self.base_url}?{query}",
            headers={
                "Accept": "application/json",
                "Key": self.api_key,
            },
        )

        with self._opener(request, timeout=self.timeout) as response:
            payload = json.load(response)

        data = payload.get("data")
        if not isinstance(data, dict):
            raise ValueError("AbuseIPDB response did not contain a valid data object")

        return AbuseIPDBResult(
            ip_address=data.get("ipAddress", ip_address),
            abuse_confidence_score=data.get("abuseConfidenceScore"),
            country_code=data.get("countryCode"),
            usage_type=data.get("usageType"),
            isp=data.get("isp"),
            domain=data.get("domain"),
            total_reports=data.get("totalReports"),
            last_reported_at=data.get("lastReportedAt"),
            is_public=data.get("isPublic"),
            is_whitelisted=data.get("isWhitelisted"),
            raw_response=payload,
        )

