from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse
from typing import Any

from ..models import NormalizedEvent

_URL_RE = re.compile(r"\bhttps?://[^\s'\"<>]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
_FILE_PATH_RE = re.compile(
    r"(?<![\w.-])(?:/[A-Za-z0-9._+@%=-]+(?:/[A-Za-z0-9._+@%=-]+)+|[A-Za-z]:\\[^\s'\"<>]+)"
)
_PAYLOAD_SUFFIXES = (".sh", ".elf", ".bin", ".exe", ".py", ".pl", ".php", ".jar", ".apk")


def _append_unique(values: list[Any], value: Any) -> None:
    if value not in values:
        values.append(value)


def _valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return False
    return True


def _extract_urls(text: str) -> list[str]:
    urls: list[str] = []
    for match in _URL_RE.finditer(text):
        url = match.group(0).rstrip(").,;]")
        _append_unique(urls, url)
    return urls


def _extract_file_paths(text: str) -> list[str]:
    paths: list[str] = []
    for match in _FILE_PATH_RE.finditer(text):
        prefix = text[max(0, match.start() - 8):match.start()].lower()
        if "http:" in prefix or "https:" in prefix:
            continue
        _append_unique(paths, match.group(0))
    return paths


def _domain_from_url(url: str) -> str | None:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return None
    return host.lower()


def _hash_type(value: str) -> str:
    length = len(value)
    if length == 32:
        return "md5"
    if length == 40:
        return "sha1"
    return "sha256"


def extract_indicators(event: NormalizedEvent) -> dict[str, list[Any]]:
    """Extract indicators from normalized fields and attacker-controlled text.

    The original broad indicator keys are kept for compatibility. More specific
    typed keys make future enrichment providers easier to add.
    """

    indicators = {
        "ip_addresses": [],
        "usernames": [],
        "passwords": [],
        "commands": [],
        "urls": [],
        "domains": [],
        "hashes": [],
        "file_paths": [],
        "payload_references": [],
    }

    if event.source_ip:
        _append_unique(indicators["ip_addresses"], event.source_ip)
    if event.username:
        _append_unique(indicators["usernames"], event.username)
    if event.password:
        _append_unique(indicators["passwords"], event.password)
    if event.command:
        _append_unique(indicators["commands"], event.command)
    if event.url:
        _append_unique(indicators["urls"], event.url)

    text_sources = [
        value
        for value in (event.command, event.url)
        if isinstance(value, str) and value
    ]

    for value in event.raw_event.values():
        if isinstance(value, str) and value:
            text_sources.append(value)

    for text in text_sources:
        for ip in _IPV4_RE.findall(text):
            if _valid_ipv4(ip):
                _append_unique(indicators["ip_addresses"], ip)

        for url in _extract_urls(text):
            _append_unique(indicators["urls"], url)

        for path in _extract_file_paths(text):
            _append_unique(indicators["file_paths"], path)

        for hash_value in _HASH_RE.findall(text):
            normalized_hash = hash_value.lower()
            _append_unique(
                indicators["hashes"],
                {"type": _hash_type(normalized_hash), "value": normalized_hash},
            )

    for url in indicators["urls"]:
        if not isinstance(url, str):
            continue
        domain = _domain_from_url(url)
        if domain:
            _append_unique(indicators["domains"], domain)
        path = urlparse(url).path.lower()
        if any(path.endswith(suffix) for suffix in _PAYLOAD_SUFFIXES):
            _append_unique(indicators["payload_references"], url)

    for path in indicators["file_paths"]:
        if not isinstance(path, str):
            continue
        lowered = path.lower()
        if any(lowered.endswith(suffix) for suffix in _PAYLOAD_SUFFIXES):
            _append_unique(indicators["payload_references"], path)

    return indicators
