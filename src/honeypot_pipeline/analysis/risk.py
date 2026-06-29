from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

_CATEGORY_POINTS = {
    "brute_force": 15,
    "reconnaissance": 10,
    "network_scan": 15,
    "command_execution": 20,
    "malware_download": 35,
    "persistence": 40,
    "destructive_action": 45,
    "cryptomining": 40,
    "privilege_escalation": 35,
    "defense_evasion": 30,
    "credential_access": 25,
    "obfuscation": 20,
    "reverse_shell": 40,
    "cloud_metadata_access": 40,
    "data_exfiltration": 35,
    "lateral_movement": 35,
    "container_escape": 40,
}

_SEVERITY_POINTS = {
    "low": 5,
    "medium": 15,
    "high": 30,
}


def risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    if score >= 15:
        return "low"
    return "minimal"


def _clamp_score(score: int) -> int:
    return max(0, min(100, score))


def score_event_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """Score a single processed event with explainable deterministic rules."""

    score = 0
    reasons: list[str] = []

    classification = record.get("classification")
    if isinstance(classification, Mapping):
        category = classification.get("attack_category")
        if isinstance(category, str):
            points = _CATEGORY_POINTS.get(category, 0)
            if points:
                score += points
                reasons.append(f"category:{category}")

        severity = classification.get("severity")
        if isinstance(severity, str):
            points = _SEVERITY_POINTS.get(severity.lower(), 0)
            if points:
                score += points
                reasons.append(f"severity:{severity.lower()}")

    event_type = record.get("event_type")
    if isinstance(event_type, str) and "login.success" in event_type:
        score += 20
        reasons.append("successful_login")

    threat_intel = record.get("threat_intel")
    if isinstance(threat_intel, Mapping):
        threat_score = threat_intel.get("score")
        if isinstance(threat_score, Mapping) and threat_score.get("is_malicious") is True:
            confidence = threat_score.get("confidence")
            score += 30 if confidence == "high" else 20
            reasons.append(f"malicious_ip:{confidence or 'unknown'}")

    indicators = record.get("indicators")
    if isinstance(indicators, Mapping):
        urls = indicators.get("urls")
        if isinstance(urls, Sequence) and not isinstance(urls, str) and len(urls) > 0:
            score += 5
            reasons.append("url_indicator")

        payloads = indicators.get("payload_references")
        if isinstance(payloads, Sequence) and not isinstance(payloads, str) and len(payloads) > 0:
            score += 10
            reasons.append("payload_reference")

        hashes = indicators.get("hashes")
        if isinstance(hashes, Sequence) and not isinstance(hashes, str) and len(hashes) > 0:
            score += 10
            reasons.append("hash_indicator")

    score = _clamp_score(score)
    return {
        "score": score,
        "level": risk_level(score),
        "reasons": reasons or ["no_risk_rule_matched"],
    }


def score_session_snapshot(
    event_count: int,
    attack_categories: Sequence[str],
    severity_counts: Mapping[str, int],
    is_malicious: bool,
) -> dict[str, Any]:
    """Score an attack session from aggregate evidence.

    This function is storage-agnostic so callers can use it with SQLite rows,
    JSONL batches, or future streaming session state.
    """

    score = 0
    reasons: list[str] = []
    categories = set(attack_categories)

    if event_count >= 25:
        score += 20
        reasons.append("high_event_volume")
    elif event_count >= 10:
        score += 10
        reasons.append("moderate_event_volume")
    elif event_count >= 3:
        score += 5
        reasons.append("multi_event_session")

    for category in sorted(categories):
        points = _CATEGORY_POINTS.get(category, 0)
        if points:
            score += points
            reasons.append(f"category:{category}")

    high_count = int(severity_counts.get("high", 0) or 0)
    medium_count = int(severity_counts.get("medium", 0) or 0)

    if high_count:
        score += min(25, high_count * 10)
        reasons.append("high_severity_events")
    if medium_count:
        score += min(15, medium_count * 5)
        reasons.append("medium_severity_events")

    if is_malicious:
        score += 25
        reasons.append("malicious_source_ip")

    # ── Combo detections ─────────────────────────────────────────────

    if "persistence" in categories and "malware_download" in categories:
        score += 15
        reasons.append("download_plus_persistence")

    if "reconnaissance" in categories and "privilege_escalation" in categories:
        score += 15
        reasons.append("recon_plus_privilege_escalation")

    if "malware_download" in categories and "cryptomining" in categories:
        score += 15
        reasons.append("download_plus_cryptomining")

    if "brute_force" in categories and "credential_access" in categories:
        score += 15
        reasons.append("credential_access_after_login")

    if "destructive_action" in categories:
        score += 10
        reasons.append("destructive_action_present")

    if "defense_evasion" in categories and "privilege_escalation" in categories:
        score += 10
        reasons.append("evasion_plus_privilege_escalation")

    if "obfuscation" in categories and "malware_download" in categories:
        score += 10
        reasons.append("obfuscated_download")

    # ── New combo rules ──────────────────────────────────────────────

    if "reverse_shell" in categories and "defense_evasion" in categories:
        score += 15
        reasons.append("reverse_shell_plus_evasion")

    if "reverse_shell" in categories and "malware_download" in categories:
        score += 15
        reasons.append("reverse_shell_plus_download")

    if "lateral_movement" in categories and "credential_access" in categories:
        score += 15
        reasons.append("lateral_movement_with_creds")

    if "cloud_metadata_access" in categories and "data_exfiltration" in categories:
        score += 20
        reasons.append("cloud_cred_theft_and_exfil")

    if "container_escape" in categories and "persistence" in categories:
        score += 20
        reasons.append("container_escape_plus_persistence")

    if "lateral_movement" in categories and "defense_evasion" in categories:
        score += 10
        reasons.append("lateral_movement_plus_evasion")

    if "network_scan" in categories and "brute_force" in categories:
        score += 10
        reasons.append("scan_plus_bruteforce")

    if "reverse_shell" in categories and "cryptomining" in categories:
        score += 10
        reasons.append("reverse_shell_plus_mining")

    score = _clamp_score(score)
    return {
        "score": score,
        "level": risk_level(score),
        "reasons": reasons or ["no_risk_rule_matched"],
    }
