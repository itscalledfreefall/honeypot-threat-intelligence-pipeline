from __future__ import annotations

import io
import json
import unittest

from honeypot_pipeline.abuseipdb import AbuseIPDBClient
from honeypot_pipeline.cowrie import normalize_cowrie_event
from honeypot_pipeline.enrichment import enrich_event_with_abuseipdb, enrich_event_with_threat_intel
from honeypot_pipeline.virustotal import VirusTotalClient


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
        provider = record["threat_intel"]["providers"]["abuseipdb"]
        self.assertTrue(provider["is_malicious"])
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


class VirusTotalTests(unittest.TestCase):
    def test_client_builds_request_and_parses_response(self) -> None:
        seen: dict[str, object] = {}

        def fake_opener(request, timeout=0):
            seen["url"] = request.full_url
            seen["accept"] = request.get_header("Accept")
            seen["key"] = request.get_header("X-apikey")
            seen["timeout"] = timeout
            payload = {
                "data": {
                    "id": "198.51.100.24",
                    "attributes": {
                        "country": "TR",
                        "as_owner": "Example ASN",
                        "network": "198.51.100.0/24",
                        "reputation": -10,
                        "last_analysis_stats": {
                            "malicious": 2,
                            "suspicious": 1,
                            "harmless": 50,
                            "undetected": 10,
                        },
                        "total_votes": {
                            "malicious": 3,
                            "harmless": 0,
                        },
                    },
                }
            }
            return _FakeHTTPResponse(json.dumps(payload).encode("utf-8"))

        client = VirusTotalClient(api_key="vt-key", opener=fake_opener)
        result = client.lookup_ip("198.51.100.24")

        self.assertTrue(str(seen["url"]).endswith("/198.51.100.24"))
        self.assertEqual(seen["accept"], "application/json")
        self.assertEqual(seen["key"], "vt-key")
        self.assertEqual(seen["timeout"], 10.0)
        self.assertEqual(result.ip_address, "198.51.100.24")
        self.assertEqual(result.malicious, 2)
        self.assertEqual(result.suspicious, 1)

    def test_multi_provider_enrichment_merges_results(self) -> None:
        class FakeAbuseClient:
            def lookup_ip(self, ip_address: str, max_age_in_days: int = 90):
                return type(
                    "Result",
                    (),
                    {
                        "abuse_confidence_score": 60,
                        "to_dict": lambda self: {"ip_address": ip_address, "abuse_confidence_score": 60},
                    },
                )()

        class FakeVirusTotalClient:
            def lookup_ip(self, ip_address: str):
                return type(
                    "Result",
                    (),
                    {
                        "malicious": 2,
                        "suspicious": 0,
                        "to_dict": lambda self: {"ip_address": ip_address, "malicious": 2},
                    },
                )()

        event = normalize_cowrie_event(
            {
                "timestamp": "2026-03-21T11:00:00.000000Z",
                "eventid": "cowrie.login.failed",
                "src_ip": "198.51.100.24",
            }
        )

        record = enrich_event_with_threat_intel(
            event,
            abuseipdb_client=FakeAbuseClient(),
            virustotal_client=FakeVirusTotalClient(),
        )

        self.assertEqual(record["threat_intel"]["status"], "completed")
        self.assertTrue(record["threat_intel"]["providers"]["abuseipdb"]["is_malicious"])
        self.assertTrue(record["threat_intel"]["providers"]["virustotal"]["is_malicious"])
        self.assertEqual(record["threat_intel"]["score"]["confidence"], "high")

    def test_multi_provider_enrichment_handles_partial_failure(self) -> None:
        class FailingAbuseClient:
            def lookup_ip(self, ip_address: str, max_age_in_days: int = 90):
                raise RuntimeError("upstream timeout")

        class FakeVirusTotalClient:
            def lookup_ip(self, ip_address: str):
                return type(
                    "Result",
                    (),
                    {
                        "malicious": 1,
                        "suspicious": 0,
                        "to_dict": lambda self: {"ip_address": ip_address, "malicious": 1},
                    },
                )()

        event = normalize_cowrie_event(
            {
                "timestamp": "2026-03-21T11:00:00.000000Z",
                "eventid": "cowrie.login.failed",
                "src_ip": "198.51.100.24",
            }
        )

        record = enrich_event_with_threat_intel(
            event,
            abuseipdb_client=FailingAbuseClient(),
            virustotal_client=FakeVirusTotalClient(),
        )

        self.assertEqual(record["threat_intel"]["status"], "partial")
        self.assertEqual(record["threat_intel"]["providers"]["abuseipdb"]["status"], "failed")
        self.assertTrue(record["threat_intel"]["providers"]["virustotal"]["is_malicious"])


if __name__ == "__main__":
    unittest.main()
