from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from honeypot_pipeline.storage import append_jsonl, write_json_document
from honeypot_pipeline.summary import PipelineSummary


class OutputTests(unittest.TestCase):
    def test_append_jsonl_writes_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "records.jsonl"
            append_jsonl(path, {"event_type": "cowrie.login.failed", "source_ip": "203.0.113.10"})
            append_jsonl(path, {"event_type": "cowrie.command.input", "source_ip": "198.51.100.24"})

            lines = path.read_text(encoding="utf-8").splitlines()

        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0])["source_ip"], "203.0.113.10")

    def test_summary_tracks_batch_counts(self) -> None:
        summary = PipelineSummary()
        summary.add_record(
            {
                "event_type": "cowrie.login.failed",
                "protocol": "ssh",
                "source_ip": "203.0.113.10",
                "classification": {"attack_category": "brute_force"},
            }
        )
        summary.add_record(
            {
                "event_type": "cowrie.command.input",
                "protocol": "ssh",
                "source_ip": "198.51.100.24",
                "classification": {"attack_category": "malware_download"},
            }
        )

        payload = summary.to_dict()

        self.assertEqual(payload["total_events"], 2)
        self.assertEqual(payload["unique_source_ips"], 2)
        self.assertEqual(payload["by_attack_category"]["brute_force"], 1)
        self.assertEqual(payload["by_protocol"]["ssh"], 2)

    def test_write_json_document_writes_pretty_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "summary.json"
            write_json_document(path, {"total_events": 2, "unique_source_ips": 1})
            payload = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(payload["total_events"], 2)


if __name__ == "__main__":
    unittest.main()
