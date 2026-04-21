from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from honeypot_pipeline.cli import iter_input_lines


class CLITests(unittest.TestCase):
    def test_iter_input_lines_reads_existing_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "events.ndjson"
            path.write_text("one\n\ntwo\n", encoding="utf-8")

            lines = list(iter_input_lines(path))

        self.assertEqual(lines, ["one\n", "\n", "two\n"])

    def test_iter_input_lines_follow_mode_stops_after_idle_limit_in_test(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "events.ndjson"
            path.write_text("one\n", encoding="utf-8")

            lines = list(
                iter_input_lines(
                    path,
                    follow=True,
                    poll_interval=0.001,
                    max_idle_polls=1,
                )
            )

        self.assertEqual(lines, ["one\n"])


if __name__ == "__main__":
    unittest.main()
