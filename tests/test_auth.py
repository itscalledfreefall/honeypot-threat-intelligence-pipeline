from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from honeypot_pipeline.dashboard import create_app
from honeypot_pipeline.storage.database import Database


class AuthDatabaseTests(unittest.TestCase):
    def test_user_registration_hashes_password_and_enforces_unique_email(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db = Database(Path(tmpdir) / "auth.db")
            db.initialize()

            user = db.create_user(
                email="Owner@Example.COM",
                password="strong-password",
                first_name="Ata",
                middle_name=None,
                cloud_provider="local_server",
            )

            self.assertTrue(user["user_id"].startswith("user_"))
            self.assertEqual(user["email"], "owner@example.com")

            with db.connection() as conn:
                stored = conn.execute(
                    "SELECT password_hash FROM users WHERE email = ?",
                    ("owner@example.com",),
                ).fetchone()

            self.assertIsNotNone(stored)
            self.assertNotEqual(stored["password_hash"], "strong-password")

            with self.assertRaises(ValueError):
                db.create_user(
                    email="owner@example.com",
                    password="another-password",
                    first_name="Other",
                    middle_name=None,
                    cloud_provider="aws",
                )
            db.close()

    def test_login_session_and_password_reset_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db = Database(Path(tmpdir) / "auth.db")
            db.initialize()
            user = db.create_user(
                email="operator@example.com",
                password="old-password",
                first_name="Operator",
                middle_name="Lab",
                cloud_provider="aws",
            )

            self.assertIsNone(db.authenticate_user("operator@example.com", "bad-password"))
            self.assertIsNotNone(db.authenticate_user("operator@example.com", "old-password"))

            session_token = db.create_session(user["user_id"])
            self.assertEqual(
                db.get_user_by_session_token(session_token)["email"],
                "operator@example.com",
            )

            reset_token = db.create_password_reset_token("operator@example.com")
            self.assertIsNotNone(reset_token)
            self.assertTrue(db.reset_password(reset_token or "", "new-password"))
            self.assertIsNone(db.get_user_by_session_token(session_token))
            self.assertIsNone(db.authenticate_user("operator@example.com", "old-password"))
            self.assertIsNotNone(db.authenticate_user("operator@example.com", "new-password"))
            db.close()


class AuthAPITests(unittest.TestCase):
    def test_register_login_me_logout_and_reset_endpoints(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            records_path = Path(tmpdir) / "records.jsonl"
            records_path.touch()
            db_path = Path(tmpdir) / "auth.db"
            app = create_app(records_path=records_path, db_path=db_path)

            with app.test_client() as client:
                register = client.post(
                    "/api/auth/register",
                    json={
                        "email": "owner@example.com",
                        "password": "strong-password",
                        "first_name": "Owner",
                        "middle_name": "",
                        "cloud_provider": "cloudflare",
                    },
                )
                self.assertEqual(register.status_code, 201)
                token = register.get_json()["token"]

                duplicate = client.post(
                    "/api/auth/register",
                    json={
                        "email": "owner@example.com",
                        "password": "strong-password",
                        "first_name": "Owner",
                        "cloud_provider": "cloudflare",
                    },
                )
                self.assertEqual(duplicate.status_code, 400)

                me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
                self.assertEqual(me.status_code, 200)
                self.assertEqual(me.get_json()["user"]["email"], "owner@example.com")

                reset = client.post(
                    "/api/auth/password-reset/request",
                    json={"email": "owner@example.com"},
                )
                self.assertEqual(reset.status_code, 200)
                reset_token = reset.get_json()["reset_token"]

                confirm = client.post(
                    "/api/auth/password-reset/confirm",
                    json={"token": reset_token, "password": "new-password"},
                )
                self.assertEqual(confirm.status_code, 200)

                old_login = client.post(
                    "/api/auth/login",
                    json={"email": "owner@example.com", "password": "strong-password"},
                )
                self.assertEqual(old_login.status_code, 401)

                new_login = client.post(
                    "/api/auth/login",
                    json={"email": "owner@example.com", "password": "new-password"},
                )
                self.assertEqual(new_login.status_code, 200)

                new_token = new_login.get_json()["token"]
                logout = client.post(
                    "/api/auth/logout",
                    headers={"Authorization": f"Bearer {new_token}"},
                )
                self.assertEqual(logout.status_code, 200)

                expired_me = client.get(
                    "/api/auth/me",
                    headers={"Authorization": f"Bearer {new_token}"},
                )
                self.assertEqual(expired_me.status_code, 401)


if __name__ == "__main__":
    unittest.main()
