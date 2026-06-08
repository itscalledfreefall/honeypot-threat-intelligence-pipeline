"""Compatibility wrapper for the VirusTotal client."""

from .enrichment.virustotal import VirusTotalClient, VirusTotalIPResult

__all__ = ["VirusTotalClient", "VirusTotalIPResult"]

