from __future__ import annotations

import argparse
import json
from pathlib import Path

from .abuseipdb import AbuseIPDBClient
from .cowrie import iter_normalized_cowrie_events
from .enrichment import enrich_event_with_threat_intel
from .records import build_event_record
from .settings import Settings
from .storage import append_jsonl, write_json_document
from .summary import PipelineSummary
from .virustotal import VirusTotalClient


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Normalize Cowrie JSON log lines into a structured event schema."
    )
    parser.add_argument("input_file", type=Path, help="Path to a Cowrie JSON-lines log file")
    parser.add_argument(
        "--enrich-abuseipdb",
        action="store_true",
        help="Query AbuseIPDB for each event source IP",
    )
    parser.add_argument(
        "--abuseipdb-api-key",
        help="API key override for AbuseIPDB. Defaults to ABUSEIPDB_API_KEY.",
    )
    parser.add_argument(
        "--enrich-virustotal",
        action="store_true",
        help="Query VirusTotal for each event source IP",
    )
    parser.add_argument(
        "--virustotal-api-key",
        help="API key override for VirusTotal. Defaults to VIRUSTOTAL_API_KEY.",
    )
    parser.add_argument(
        "--malicious-threshold",
        type=int,
        default=50,
        help="Abuse confidence score threshold used to mark an IP as malicious.",
    )
    parser.add_argument(
        "--virustotal-malicious-threshold",
        type=int,
        default=1,
        help="Minimum VirusTotal malicious+suspicious detections used to mark an IP as malicious.",
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        help="Optional JSONL file for writing processed records.",
    )
    parser.add_argument(
        "--summary-file",
        type=Path,
        help="Optional JSON summary file describing the processed batch.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    settings = Settings.from_env()
    abuseipdb_api_key = args.abuseipdb_api_key or settings.abuseipdb_api_key
    virustotal_api_key = args.virustotal_api_key or settings.virustotal_api_key
    abuseipdb_client = None
    virustotal_client = None
    summary = PipelineSummary()

    if args.enrich_abuseipdb:
        if not abuseipdb_api_key:
            parser.error(
                "AbuseIPDB enrichment requires --abuseipdb-api-key or ABUSEIPDB_API_KEY"
            )
        abuseipdb_client = AbuseIPDBClient(
            api_key=abuseipdb_api_key,
            base_url=settings.abuseipdb_base_url,
        )
    if args.enrich_virustotal:
        if not virustotal_api_key:
            parser.error(
                "VirusTotal enrichment requires --virustotal-api-key or VIRUSTOTAL_API_KEY"
            )
        virustotal_client = VirusTotalClient(
            api_key=virustotal_api_key,
            base_url=settings.virustotal_base_url,
        )

    with args.input_file.open("r", encoding="utf-8") as handle:
        for event in iter_normalized_cowrie_events(handle):
            if abuseipdb_client is not None or virustotal_client is not None:
                record = enrich_event_with_threat_intel(
                    event,
                    abuseipdb_client=abuseipdb_client,
                    virustotal_client=virustotal_client,
                    abuseipdb_malicious_threshold=args.malicious_threshold,
                    virustotal_malicious_threshold=args.virustotal_malicious_threshold,
                )
            else:
                record = build_event_record(event)

            summary.add_record(record)
            print(json.dumps(record, ensure_ascii=True))

            if args.output_file is not None:
                append_jsonl(args.output_file, record)

    if args.summary_file is not None:
        write_json_document(args.summary_file, summary.to_dict())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
