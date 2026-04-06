from __future__ import annotations

import io
import json
import unittest

from honeypot_pipeline.abuseipdb import AbuseIPDBClient
from honeypot_pipeline.cowrie import normalize_cowrie_event
from honeypot_pipeline.enrichment import enrich_event_with_abuseipdb


class _FakeHTTPResponse(io.BytesIO):
    def __enter__(self) -> "_FakeHTTPResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class AbuseIPDBTests(unittest.TestCase):
    def test_client_builds_request_and_parses_response(self) -> None:
        seen: dict[str, object] = {}

        def fake_opener(request, timeout=0):
            seen["url"] = request.full_url
            seen["accept"] = request.get_header("Accept")
            seen["key"] = request.get_header("Key")
            seen["timeout"] = timeout
            payload = {
                "data": {
                    "ipAddress": "203.0.113.10",
                    "abuseConfidenceScore": 87,
                    "countryCode": "TR",
                    "usageType": "Data Center/Web Hosting/Transit",
                    "isp": "Example ISP",
                    "domain": "example.invalid",
                    "totalReports": 14,
                    "lastReportedAt": "2026-03-21T10:00:00+00:00",
                    "isPublic": True,
                    "isWhitelisted": False,
                }
            }
            return _FakeHTTPResponse(json.dumps(payload).encode("utf-8"))

        client = AbuseIPDBClient(api_key="secret-key", opener=fake_opener)
        result = client.lookup_ip("203.0.113.10", max_age_in_days=30)

        self.assertIn("ipAddress=203.0.113.10", seen["url"])
        self.assertIn("maxAgeInDays=30", seen["url"])
        self.assertEqual(seen["accept"], "application/json")
        self.assertEqual(seen["key"], "secret-key")
        self.assertEqual(seen["timeout"], 10.0)
        self.assertEqual(result.ip_address, "203.0.113.10")
        self.assertEqual(result.abuse_confidence_score, 87)
        self.assertEqual(result.total_reports, 14)

    def test_enrichment_marks_event_as_malicious_when_threshold_is_met(self) -> None:
        class FakeClient:
            def lookup_ip(self, ip_address: str, max_age_in_days: int = 90):
                self.ip_address = ip_address
                self.max_age_in_days = max_age_in_days
                return type(
                    "Result",
                    (),
                    {
                        "abuse_confidence_score": 75,
                        "to_dict": lambda self: {
                            "ip_address": "198.51.100.24",
                            "abuse_confidence_score": 75,
                        },
                    },
                )()

        event = normalize_cowrie_event(
            {
                "timestamp": "2026-03-21T11:00:00.000000Z",
                "eventid": "cowrie.login.failed",
                "src_ip": "198.51.100.24",
                "username": "admin",
                "password": "admin",
            }
        )

        client = FakeClient()
        record = enrich_event_with_abuseipdb(event, client=client, malicious_threshold=50)

        self.assertEqual(client.ip_address, "198.51.100.24")
        self.assertEqual(record["threat_intel"]["provider"], "abuseipdb")
        self.assertTrue(record["threat_intel"]["is_malicious"])
        self.assertEqual(record["indicators"]["usernames"], ["admin"])

    def test_enrichment_skips_events_without_source_ip(self) -> None:
        class NeverCalledClient:
            def lookup_ip(self, ip_address: str, max_age_in_days: int = 90):
                raise AssertionError("lookup_ip should not be called")

        event = normalize_cowrie_event(
            {
                "timestamp": "2026-03-21T11:05:00.000000Z",
                "eventid": "cowrie.session.file_download",
                "url": "http://bad.example/file.sh",
            }
        )

        record = enrich_event_with_abuseipdb(event, client=NeverCalledClient())

        self.assertEqual(record["threat_intel"]["status"], "skipped")
        self.assertEqual(record["threat_intel"]["reason"], "missing_source_ip")


if __name__ == "__main__":
    unittest.main()
