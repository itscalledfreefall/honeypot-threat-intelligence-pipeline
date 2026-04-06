from __future__ import annotations

import argparse
import json
from pathlib import Path

from .abuseipdb import AbuseIPDBClient
from .cowrie import iter_normalized_cowrie_events
from .enrichment import enrich_event_with_abuseipdb
from .records import build_event_record
from .settings import Settings
from .storage import append_jsonl, write_json_document
from .summary import PipelineSummary


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
        "--malicious-threshold",
        type=int,
        default=50,
        help="Abuse confidence score threshold used to mark an IP as malicious.",
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
    api_key = args.abuseipdb_api_key or settings.abuseipdb_api_key
    client = None
    summary = PipelineSummary()

    if args.enrich_abuseipdb:
        if not api_key:
            parser.error(
                "AbuseIPDB enrichment requires --abuseipdb-api-key or ABUSEIPDB_API_KEY"
            )
        client = AbuseIPDBClient(
            api_key=api_key,
            base_url=settings.abuseipdb_base_url,
        )

    with args.input_file.open("r", encoding="utf-8") as handle:
        for event in iter_normalized_cowrie_events(handle):
            if client is not None:
                record = enrich_event_with_abuseipdb(
                    event,
                    client=client,
                    malicious_threshold=args.malicious_threshold,
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
