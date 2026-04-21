"""Core package for the honeypot threat-intelligence pipeline."""

from .abuseipdb import AbuseIPDBClient, AbuseIPDBResult
from .classification import classify_event
from .cowrie import iter_normalized_cowrie_events, normalize_cowrie_event
from .enrichment import enrich_event_with_abuseipdb, enrich_event_with_threat_intel
from .ioc import extract_indicators
from .models import NormalizedEvent
from .reporting import (
    build_markdown_report,
    collect_blocklist_ips,
    export_report_bundle,
    get_malicious_records,
    is_record_malicious,
)
from .records import build_event_record
from .settings import Settings
from .summary import PipelineSummary
from .virustotal import VirusTotalClient, VirusTotalIPResult

try:
    from .dashboard import create_app
    from .dashboard_data import DashboardDataset, filter_records, load_dataset, load_records
except ModuleNotFoundError:  # pragma: no cover - optional dashboard dependency
    create_app = None
    DashboardDataset = None
    filter_records = None
    load_dataset = None
    load_records = None

__all__ = [
    "AbuseIPDBClient",
    "AbuseIPDBResult",
    "DashboardDataset",
    "NormalizedEvent",
    "PipelineSummary",
    "Settings",
    "VirusTotalClient",
    "VirusTotalIPResult",
    "build_markdown_report",
    "build_event_record",
    "classify_event",
    "collect_blocklist_ips",
    "create_app",
    "enrich_event_with_abuseipdb",
    "enrich_event_with_threat_intel",
    "export_report_bundle",
    "extract_indicators",
    "filter_records",
    "get_malicious_records",
    "is_record_malicious",
    "iter_normalized_cowrie_events",
    "load_dataset",
    "load_records",
    "normalize_cowrie_event",
]
