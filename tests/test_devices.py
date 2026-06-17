from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from honeypot_pipeline.dashboard import create_app
from honeypot_pipeline.storage.database import Database

AGENT_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "device-agent.py"


class DeviceAgentScriptTests(unittest.TestCase):
    @unittest.skipIf(os.geteuid() == 0, "needs a non-root user to test the guard")
    def test_install_service_requires_root(self) -> None:
        result = subprocess.run(
            [sys.executable, str(AGENT_SCRIPT), "--install-service",
             "--api-url", "http://localhost:5000", "--token", "x"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("root", result.stdout.lower())


class DeviceDatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmpdir.name) / "devices.db")
        self.db.initialize()
        self.user = self.db.create_user(
            email="operator@example.com",
            password="strong-password",
            first_name="Operator",
            middle_name=None,
            cloud_provider="local_server",
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tmpdir.cleanup()

    def test_create_device_returns_one_time_token(self) -> None:
        device = self.db.create_device(
            user_id=self.user["user_id"], name="edge-vm", provider="AWS"
        )
        self.assertTrue(device["device_id"].startswith("device_"))
        self.assertEqual(device["provider"], "aws")
        self.assertEqual(device["status"], "offline")
        self.assertIn("token", device)

        # token is stored hashed, never in plaintext
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT token_hash FROM devices WHERE device_id = ?",
                (device["device_id"],),
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertNotEqual(row["token_hash"], device["token"])

    def test_create_device_requires_name(self) -> None:
        with self.assertRaises(ValueError):
            self.db.create_device(user_id=self.user["user_id"], name="  ", provider=None)

    def test_heartbeat_updates_metrics_and_status(self) -> None:
        device = self.db.create_device(
            user_id=self.user["user_id"], name="edge-vm", provider=None
        )
        token = device["token"]

        result = self.db.record_heartbeat(
            token,
            {
                "hostname": "edge-vm",
                "ram_used_mb": 512,
                "ram_total_mb": 1024,
                "ram_percent": 50.0,
                "secret": "ignored",  # not a whitelisted key
            },
        )
        self.assertEqual(result, device["device_id"])

        devices = self.db.list_devices(self.user["user_id"])
        self.assertEqual(len(devices), 1)
        d = devices[0]
        self.assertEqual(d["status"], "online")
        self.assertEqual(d["hostname"], "edge-vm")
        self.assertEqual(d["metrics"]["ram_percent"], 50.0)
        self.assertNotIn("secret", d["metrics"])

    def test_invalid_token_heartbeat_is_rejected(self) -> None:
        self.db.create_device(user_id=self.user["user_id"], name="edge-vm", provider=None)
        self.assertIsNone(self.db.record_heartbeat("not-a-real-token", {"hostname": "x"}))

    def test_status_changes_with_heartbeat_age(self) -> None:
        device = self.db.create_device(
            user_id=self.user["user_id"], name="edge-vm", provider=None
        )
        self.db.record_heartbeat(device["token"], {"hostname": "edge-vm"})

        # Force last_seen into the past to simulate ageing.
        with self.db.connection() as conn:
            conn.execute(
                "UPDATE devices SET last_seen = datetime('now', '-5 minutes') WHERE device_id = ?",
                (device["device_id"],),
            )
            conn.commit()
        self.assertEqual(self.db.list_devices(self.user["user_id"])[0]["status"], "stale")

        with self.db.connection() as conn:
            conn.execute(
                "UPDATE devices SET last_seen = datetime('now', '-30 minutes') WHERE device_id = ?",
                (device["device_id"],),
            )
            conn.commit()
        self.assertEqual(self.db.list_devices(self.user["user_id"])[0]["status"], "offline")

    def test_delete_device_is_scoped_to_owner(self) -> None:
        other = self.db.create_user(
            email="other@example.com",
            password="strong-password",
            first_name="Other",
            middle_name=None,
            cloud_provider="aws",
        )
        device = self.db.create_device(user_id=self.user["user_id"], name="mine", provider=None)
        # another user cannot delete it
        self.assertFalse(self.db.delete_device(other["user_id"], device["device_id"]))
        # owner can
        self.assertTrue(self.db.delete_device(self.user["user_id"], device["device_id"]))

    def test_devices_are_scoped_to_user(self) -> None:
        other = self.db.create_user(
            email="other@example.com",
            password="strong-password",
            first_name="Other",
            middle_name=None,
            cloud_provider="aws",
        )
        self.db.create_device(user_id=self.user["user_id"], name="mine", provider=None)
        self.assertEqual(len(self.db.list_devices(self.user["user_id"])), 1)
        self.assertEqual(len(self.db.list_devices(other["user_id"])), 0)


class DeviceAPITests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        records_path = Path(self.tmpdir.name) / "records.jsonl"
        records_path.touch()
        self.app = create_app(
            records_path=records_path,
            db_path=Path(self.tmpdir.name) / "devices.db",
        )
        self.client = self.app.test_client()
        register = self.client.post(
            "/api/auth/register",
            json={
                "email": "owner@example.com",
                "password": "strong-password",
                "first_name": "Owner",
                "cloud_provider": "aws",
            },
        )
        self.token = register.get_json()["token"]

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def _auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    def test_authenticated_user_can_create_device(self) -> None:
        resp = self.client.post(
            "/api/devices", json={"name": "edge-vm", "provider": "aws"}, headers=self._auth()
        )
        self.assertEqual(resp.status_code, 201)
        body = resp.get_json()
        self.assertIn("agent_token", body)
        self.assertIn("install_command", body)
        self.assertEqual(body["device"]["name"], "edge-vm")

    def test_unauthenticated_cannot_create_or_list_devices(self) -> None:
        self.assertEqual(self.client.post("/api/devices", json={"name": "x"}).status_code, 401)
        self.assertEqual(self.client.get("/api/devices").status_code, 401)

    def test_heartbeat_with_valid_token_updates_metrics(self) -> None:
        create = self.client.post(
            "/api/devices", json={"name": "edge-vm"}, headers=self._auth()
        )
        agent_token = create.get_json()["agent_token"]

        beat = self.client.post(
            "/api/devices/heartbeat",
            json={"metrics": {"hostname": "edge-vm", "ram_percent": 42.0}},
            headers={"Authorization": f"Bearer {agent_token}"},
        )
        self.assertEqual(beat.status_code, 200)

        listing = self.client.get("/api/devices", headers=self._auth()).get_json()
        self.assertEqual(listing["devices"][0]["status"], "online")
        self.assertEqual(listing["devices"][0]["metrics"]["ram_percent"], 42.0)

    def test_install_command_installs_systemd_service(self) -> None:
        create = self.client.post(
            "/api/devices", json={"name": "edge-vm"}, headers=self._auth()
        )
        cmd = create.get_json()["install_command"]
        self.assertIn("/api/devices/agent.py", cmd)
        self.assertIn("--install-service", cmd)

    def test_agent_script_is_served(self) -> None:
        resp = self.client.get("/api/devices/agent.py")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"collect_metrics", resp.data)

    def test_user_can_delete_own_device(self) -> None:
        create = self.client.post(
            "/api/devices", json={"name": "edge-vm"}, headers=self._auth()
        )
        device_id = create.get_json()["device"]["device_id"]

        deleted = self.client.delete(f"/api/devices/{device_id}", headers=self._auth())
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(self.client.get("/api/devices", headers=self._auth()).get_json()["devices"], [])

        # second delete now 404s
        again = self.client.delete(f"/api/devices/{device_id}", headers=self._auth())
        self.assertEqual(again.status_code, 404)

    def test_delete_device_requires_auth(self) -> None:
        create = self.client.post(
            "/api/devices", json={"name": "edge-vm"}, headers=self._auth()
        )
        device_id = create.get_json()["device"]["device_id"]
        self.assertEqual(self.client.delete(f"/api/devices/{device_id}").status_code, 401)

    def test_heartbeat_with_invalid_token_is_rejected(self) -> None:
        beat = self.client.post(
            "/api/devices/heartbeat",
            json={"metrics": {"hostname": "x"}},
            headers={"Authorization": "Bearer bogus-token"},
        )
        self.assertEqual(beat.status_code, 401)


if __name__ == "__main__":
    unittest.main()
