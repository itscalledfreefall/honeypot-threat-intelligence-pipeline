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

    def test_iter_input_lines_follows_across_rotation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "cowrie.json"
            path.write_text("first\n", encoding="utf-8")

            gen = iter_input_lines(
                path, follow=True, poll_interval=0.001, max_idle_polls=3
            )
            self.assertEqual(next(gen), "first\n")

            # Cowrie rotates: the current log is renamed and a fresh file
            # takes its place at the same path (a new inode).
            path.rename(Path(tmpdir) / "cowrie.json.2026-06-06")
            path.write_text("second\n", encoding="utf-8")

            self.assertEqual(next(gen), "second\n")
            gen.close()

    def test_iter_input_lines_follows_after_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "cowrie.json"
            path.write_text("aaaaaaaa\n", encoding="utf-8")

            gen = iter_input_lines(
                path, follow=True, poll_interval=0.001, max_idle_polls=3
            )
            self.assertEqual(next(gen), "aaaaaaaa\n")

            # File truncated and rewritten in place (same inode, smaller).
            path.write_text("b\n", encoding="utf-8")

            self.assertEqual(next(gen), "b\n")
            gen.close()


if __name__ == "__main__":
    unittest.main()
