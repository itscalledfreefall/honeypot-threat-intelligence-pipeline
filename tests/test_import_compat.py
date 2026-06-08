from __future__ import annotations

import unittest


class ImportCompatibilityTests(unittest.TestCase):
    def test_old_and_new_parser_imports_work(self) -> None:
        from honeypot_pipeline.cowrie import normalize_cowrie_event as old_import
        from honeypot_pipeline.parsers.cowrie import normalize_cowrie_event as new_import

        self.assertIs(old_import, new_import)

    def test_old_and_new_analysis_imports_work(self) -> None:
        from honeypot_pipeline.ioc import extract_indicators as old_import
        from honeypot_pipeline.analysis.ioc import extract_indicators as new_import

        self.assertIs(old_import, new_import)

    def test_package_entrypoint_imports_work(self) -> None:
        from honeypot_pipeline.dashboard import main as dashboard_main
        from honeypot_pipeline.reporting import main as reporting_main
        from honeypot_pipeline.response import main as response_main

        self.assertTrue(callable(dashboard_main))
        self.assertTrue(callable(reporting_main))
        self.assertTrue(callable(response_main))

    def test_storage_and_enrichment_public_imports_work(self) -> None:
        from honeypot_pipeline.enrichment import enrich_event_with_threat_intel
        from honeypot_pipeline.storage import append_jsonl

        self.assertTrue(callable(enrich_event_with_threat_intel))
        self.assertTrue(callable(append_jsonl))


if __name__ == "__main__":
    unittest.main()

