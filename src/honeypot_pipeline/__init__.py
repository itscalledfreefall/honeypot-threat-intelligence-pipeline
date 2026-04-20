"""Core package for the honeypot threat-intelligence pipeline."""

from .classification import classify_event
from .abuseipdb import AbuseIPDBClient, AbuseIPDBResult
from .cowrie import iter_normalized_cowrie_events, normalize_cowrie_event
from .dashboard import create_app
from .dashboard_data import DashboardDataset, filter_records, load_dataset, load_records
from .enrichment import enrich_event_with_abuseipdb, enrich_event_with_threat_intel
from .ioc import extract_indicators
from .models import NormalizedEvent
from .records import build_event_record
from .settings import Settings
from .summary import PipelineSummary
from .virustotal import VirusTotalClient, VirusTotalIPResult

__all__ = [
    "AbuseIPDBClient",
    "AbuseIPDBResult",
    "DashboardDataset",
    "NormalizedEvent",
    "PipelineSummary",
    "Settings",
    "VirusTotalClient",
    "VirusTotalIPResult",
    "build_event_record",
    "classify_event",
    "create_app",
    "enrich_event_with_abuseipdb",
    "enrich_event_with_threat_intel",
    "extract_indicators",
    "filter_records",
    "iter_normalized_cowrie_events",
    "load_dataset",
    "load_records",
    "normalize_cowrie_event",
]
