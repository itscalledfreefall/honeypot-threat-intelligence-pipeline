from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Callable
from urllib.request import Request, urlopen


@dataclass(slots=True)
class VirusTotalIPResult:
    ip_address: str
    malicious: int | None
    suspicious: int | None
    harmless: int | None
    undetected: int | None
    reputation: int | None
    country: str | None
    as_owner: str | None
    network: str | None
    total_votes_malicious: int | None
    total_votes_harmless: int | None
    raw_response: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class VirusTotalClient:
    def __init__(
        self,
        api_key: str,
        base_url: str = "https://www.virustotal.com/api/v3/ip_addresses",
        timeout: float = 10.0,
        opener: Callable[..., Any] | None = None,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._opener = opener or urlopen

    def lookup_ip(self, ip_address: str) -> VirusTotalIPResult:
        request = Request(
            f"{self.base_url}/{ip_address}",
            headers={
                "Accept": "application/json",
                "X-Apikey": self.api_key,
            },
        )

        with self._opener(request, timeout=self.timeout) as response:
            payload = json.load(response)

        data = payload.get("data")
        if not isinstance(data, dict):
            raise ValueError("VirusTotal response did not contain a valid data object")

        attributes = data.get("attributes")
        if not isinstance(attributes, dict):
            raise ValueError("VirusTotal response did not contain valid attributes")

        analysis_stats = attributes.get("last_analysis_stats")
        if not isinstance(analysis_stats, dict):
            analysis_stats = {}

        total_votes = attributes.get("total_votes")
        if not isinstance(total_votes, dict):
            total_votes = {}

        return VirusTotalIPResult(
            ip_address=str(data.get("id", ip_address)),
            malicious=analysis_stats.get("malicious"),
            suspicious=analysis_stats.get("suspicious"),
            harmless=analysis_stats.get("harmless"),
            undetected=analysis_stats.get("undetected"),
            reputation=attributes.get("reputation"),
            country=attributes.get("country"),
            as_owner=attributes.get("as_owner"),
            network=attributes.get("network"),
            total_votes_malicious=total_votes.get("malicious"),
            total_votes_harmless=total_votes.get("harmless"),
            raw_response=payload,
        )
