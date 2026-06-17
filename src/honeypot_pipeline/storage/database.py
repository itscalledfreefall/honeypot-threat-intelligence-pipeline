"""Persistent SQLite storage for honeypot events, threat intel, and attack sessions.

Uses WAL mode for concurrent read/write. Schema is designed to be trivially
portable to PostgreSQL when needed.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ..analysis.risk import score_session_snapshot
from ..auth import (
    AuthError,
    generate_token,
    hash_password,
    hash_token,
    public_user,
    validate_cloud_provider,
    validate_email,
    verify_password,
)

DDL_STATEMENTS = [
    # ── Events ──────────────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS events (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp       TEXT,
        event_type      TEXT    NOT NULL,
        honeypot        TEXT    NOT NULL DEFAULT 'cowrie',
        source_ip       TEXT,
        source_port     INTEGER,
        destination_ip  TEXT,
        destination_port INTEGER,
        protocol        TEXT,
        session_id      TEXT,
        username        TEXT,
        password        TEXT,
        command         TEXT,
        url             TEXT,
        raw_event       TEXT    NOT NULL,   -- JSON string
        attack_category TEXT,
        severity        TEXT,
        classification_reason TEXT,
        is_malicious    INTEGER DEFAULT 0,
        risk_score      INTEGER DEFAULT 0,
        risk_level      TEXT    DEFAULT 'minimal',
        risk_reasons    TEXT    DEFAULT '[]',
        created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_events_timestamp       ON events(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_events_source_ip       ON events(source_ip)",
    "CREATE INDEX IF NOT EXISTS idx_events_event_type       ON events(event_type)",
    "CREATE INDEX IF NOT EXISTS idx_events_session_id       ON events(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_attack_category  ON events(attack_category)",
    "CREATE INDEX IF NOT EXISTS idx_events_is_malicious     ON events(is_malicious)",
    "CREATE INDEX IF NOT EXISTS idx_events_risk_level       ON events(risk_level)",
    "CREATE INDEX IF NOT EXISTS idx_events_honeypot         ON events(honeypot)",
    "CREATE INDEX IF NOT EXISTS idx_events_protocol         ON events(protocol)",
    "CREATE INDEX IF NOT EXISTS idx_events_created_at       ON events(created_at)",

    # ── Threat Intel ────────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS threat_intel (
        id                      INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id                INTEGER NOT NULL UNIQUE,
        source_ip               TEXT    NOT NULL,
        status                  TEXT    NOT NULL,
        abuseipdb_score         INTEGER,
        abuseipdb_is_malicious  INTEGER DEFAULT 0,
        virustotal_malicious    INTEGER,
        virustotal_suspicious   INTEGER,
        virustotal_is_malicious INTEGER DEFAULT 0,
        combined_is_malicious   INTEGER DEFAULT 0,
        combined_confidence     TEXT,
        raw_result              TEXT    NOT NULL,   -- JSON string
        created_at              TEXT    NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_threat_intel_source_ip             ON threat_intel(source_ip)",
    "CREATE INDEX IF NOT EXISTS idx_threat_intel_status                ON threat_intel(status)",
    "CREATE INDEX IF NOT EXISTS idx_threat_intel_combined_is_malicious ON threat_intel(combined_is_malicious)",

    # ── Attack Sessions ────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS attack_sessions (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id        TEXT    NOT NULL,
        source_ip         TEXT    NOT NULL,
        honeypot          TEXT    NOT NULL,
        start_time        TEXT,
        end_time          TEXT,
        event_count       INTEGER DEFAULT 0,
        attack_categories TEXT    DEFAULT '[]',  -- JSON array
        severity_counts   TEXT    DEFAULT '{}',  -- JSON object {high:N, medium:N, low:N}
        is_malicious      INTEGER DEFAULT 0,
        risk_score        INTEGER DEFAULT 0,
        risk_level        TEXT    DEFAULT 'minimal',
        risk_reasons      TEXT    DEFAULT '[]',
        first_seen        TEXT    NOT NULL DEFAULT (datetime('now')),
        last_seen         TEXT    NOT NULL DEFAULT (datetime('now')),
        UNIQUE(session_id, source_ip)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_attack_sessions_source_ip    ON attack_sessions(source_ip)",
    "CREATE INDEX IF NOT EXISTS idx_attack_sessions_session_id   ON attack_sessions(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_attack_sessions_is_malicious ON attack_sessions(is_malicious)",
    "CREATE INDEX IF NOT EXISTS idx_attack_sessions_risk_level   ON attack_sessions(risk_level)",
    "CREATE INDEX IF NOT EXISTS idx_attack_sessions_last_seen    ON attack_sessions(last_seen)",
]

SCHEMA_COLUMNS = {
    "events": {
        "risk_score": "INTEGER DEFAULT 0",
        "risk_level": "TEXT DEFAULT 'minimal'",
        "risk_reasons": "TEXT DEFAULT '[]'",
    },
    "attack_sessions": {
        "risk_score": "INTEGER DEFAULT 0",
        "risk_level": "TEXT DEFAULT 'minimal'",
        "risk_reasons": "TEXT DEFAULT '[]'",
    },
}

MIGRATIONS: list[tuple[str, str]] = [
    (
        "0001_create_auth_tables",
        """
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         TEXT NOT NULL UNIQUE,
            email           TEXT NOT NULL UNIQUE,
            first_name      TEXT NOT NULL,
            middle_name     TEXT,
            cloud_provider  TEXT NOT NULL,
            password_hash   TEXT NOT NULL,
            created_at      TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        CREATE INDEX IF NOT EXISTS idx_users_user_id ON users(user_id);

        CREATE TABLE IF NOT EXISTS user_sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     TEXT NOT NULL,
            token_hash  TEXT NOT NULL UNIQUE,
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at  TEXT NOT NULL,
            revoked_at  TEXT,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_user_sessions_token_hash ON user_sessions(token_hash);

        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     TEXT NOT NULL,
            token_hash  TEXT NOT NULL UNIQUE,
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at  TEXT NOT NULL,
            used_at     TEXT,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
        CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token_hash ON password_reset_tokens(token_hash);
        """,
    ),
    (
        "0002_create_devices_table",
        """
        CREATE TABLE IF NOT EXISTS devices (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id       TEXT NOT NULL UNIQUE,
            user_id         TEXT NOT NULL,
            name            TEXT NOT NULL,
            provider        TEXT,
            token_hash      TEXT NOT NULL UNIQUE,
            hostname        TEXT,
            last_seen       TEXT,
            latest_metrics  TEXT,
            created_at      TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);
        CREATE INDEX IF NOT EXISTS idx_devices_token_hash ON devices(token_hash);
        """,
    ),
]

DEDUP_WINDOW_SECONDS = 60

# Device heartbeat freshness thresholds (seconds).
DEVICE_ONLINE_SECONDS = 60
DEVICE_STALE_SECONDS = 600

# Metric keys accepted from agent heartbeats.  Anything else is dropped so
# attacker-controlled data cannot smuggle unexpected fields into storage.
DEVICE_METRIC_KEYS = frozenset(
    {
        "hostname",
        "uptime_seconds",
        "ram_used_mb",
        "ram_total_mb",
        "ram_percent",
        "load_1m",
        "load_5m",
        "load_15m",
        "cpu_count",
        "disk_used_gb",
        "disk_total_gb",
        "disk_percent",
        "local_ip",
        "service_time",
    }
)

# ── Public API ────────────────────────────────────────────────────────────


class Database:
    """SQLite-backed persistent store for the honeypot pipeline."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self._conn: sqlite3.Connection | None = None

    # ── Connection management ──────────────────────────────────────────

    @contextmanager
    def connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Yield a connection, creating it on first use.  WAL mode is
        enabled so that the dashboard can read while the pipeline writes."""
        if self._conn is None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        yield self._conn

    def initialize(self) -> None:
        """Create tables and indexes if they do not exist."""
        with self.connection() as conn:
            for stmt in DDL_STATEMENTS:
                conn.execute(stmt)
            self._apply_migrations(conn)
            self._ensure_columns(conn)
            conn.commit()

    def _apply_migrations(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version     TEXT PRIMARY KEY,
                applied_at  TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        applied = {
            row["version"]
            for row in conn.execute("SELECT version FROM schema_migrations").fetchall()
        }
        for version, sql in MIGRATIONS:
            if version in applied:
                continue
            conn.executescript(sql)
            conn.execute(
                "INSERT INTO schema_migrations (version) VALUES (?)",
                (version,),
            )

    def _ensure_columns(self, conn: sqlite3.Connection) -> None:
        """Add columns introduced after the initial schema.

        This keeps demo servers usable when an existing SQLite volume is reused.
        """
        for table, columns in SCHEMA_COLUMNS.items():
            existing = {
                row["name"]
                for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
            }
            for column, definition in columns.items():
                if column not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # ── Event storage ───────────────────────────────────────────────────

    def insert_event(
        self,
        record: dict[str, Any],
        dedup_window: int = DEDUP_WINDOW_SECONDS,
    ) -> int | None:
        """Insert an event record.  Returns the new row id, or *None* if a
        duplicate was detected within *dedup_window* seconds.

        Duplicate check groups by (source_ip, session_id, event_type,
        command) within the window.
        """
        source_ip = record.get("source_ip") or ""
        session_id = record.get("session_id") or ""
        event_type = record.get("event_type", "")
        command = record.get("command") or ""
        timestamp = record.get("timestamp") or ""

        classification = record.get("classification") or {}
        threat_intel = record.get("threat_intel") or {}
        score = threat_intel.get("score") or {}
        risk = record.get("risk") or {}

        with self.connection() as conn:
            # -- dedup check -------------------------------------------------
            if source_ip and session_id and event_type:
                existing = conn.execute(
                    """
                    SELECT id FROM events
                     WHERE source_ip  = ?
                       AND session_id  = ?
                       AND event_type  = ?
                       AND command IS ?
                       AND datetime(timestamp) >= datetime(?, '-' || ? || ' seconds')
                     LIMIT 1
                    """,
                    (source_ip, session_id, event_type,
                     command or None,
                     timestamp, str(dedup_window)),
                ).fetchone()
                if existing is not None:
                    return None  # duplicate

            # -- insert ------------------------------------------------------
            cursor = conn.execute(
                """
                INSERT INTO events (
                    timestamp, event_type, honeypot,
                    source_ip, source_port, destination_ip, destination_port,
                    protocol, session_id, username, password, command, url,
                    raw_event, attack_category, severity, classification_reason,
                    is_malicious, risk_score, risk_level, risk_reasons
                ) VALUES (
                    :timestamp, :event_type, :honeypot,
                    :source_ip, :source_port, :destination_ip, :destination_port,
                    :protocol, :session_id, :username, :password, :command, :url,
                    :raw_event, :attack_category, :severity, :classification_reason,
                    :is_malicious, :risk_score, :risk_level, :risk_reasons
                )
                """,
                {
                    "timestamp": timestamp,
                    "event_type": event_type,
                    "honeypot": record.get("honeypot", "cowrie"),
                    "source_ip": source_ip or None,
                    "source_port": record.get("source_port"),
                    "destination_ip": record.get("destination_ip") or None,
                    "destination_port": record.get("destination_port"),
                    "protocol": record.get("protocol") or None,
                    "session_id": session_id or None,
                    "username": record.get("username") or None,
                    "password": record.get("password") or None,
                    "command": command or None,
                    "url": record.get("url") or None,
                    "raw_event": json.dumps(record.get("raw_event", {}), ensure_ascii=True),
                    "attack_category": classification.get("attack_category") or None,
                    "severity": classification.get("severity") or None,
                    "classification_reason": classification.get("reason") or None,
                    "is_malicious": 1 if score.get("is_malicious") else 0,
                    "risk_score": int(risk.get("score") or 0),
                    "risk_level": risk.get("level") or "minimal",
                    "risk_reasons": json.dumps(risk.get("reasons") or [], ensure_ascii=True),
                },
            )
            conn.commit()
            return cursor.lastrowid

    def query_events(
        self,
        source_ip: str | None = None,
        event_type: str | None = None,
        attack_category: str | None = None,
        protocol: str | None = None,
        malicious_only: bool = False,
        session_id: str | None = None,
        limit: int = 500,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        """Return filtered events plus total matching count."""
        where: list[str] = []
        params: list[Any] = []

        if source_ip:
            where.append("e.source_ip LIKE ?")
            params.append(f"{source_ip}%")
        if event_type:
            where.append("e.event_type = ?")
            params.append(event_type)
        if attack_category:
            where.append("e.attack_category = ?")
            params.append(attack_category)
        if protocol:
            where.append("e.protocol = ?")
            params.append(protocol)
        if malicious_only:
            where.append("e.is_malicious = 1")
        if session_id:
            where.append("e.session_id = ?")
            params.append(session_id)

        where_clause = " AND ".join(where) if where else "1=1"

        with self.connection() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) FROM events e WHERE {where_clause}",
                params,
            ).fetchone()[0]

            rows = conn.execute(
                f"""
                SELECT e.*,
                       ti.status             AS ti_status,
                       ti.combined_confidence AS ti_confidence,
                       ti.combined_is_malicious AS ti_is_malicious
                  FROM events e
                  LEFT JOIN threat_intel ti ON ti.event_id = e.id
                 WHERE {where_clause}
                 ORDER BY e.timestamp DESC
                 LIMIT ? OFFSET ?
                """,
                params + [limit, offset],
            ).fetchall()

        events: list[dict[str, Any]] = []
        for r in rows:
            d = _row_to_dict(r)
            if d is not None:
                events.append(d)
        return events, total

    def get_event_by_id(self, event_id: int) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT e.*,
                       ti.status               AS ti_status,
                       ti.combined_confidence  AS ti_confidence,
                       ti.combined_is_malicious AS ti_is_malicious,
                       ti.raw_result           AS ti_raw_result,
                       ti.abuseipdb_score,
                       ti.abuseipdb_is_malicious,
                       ti.virustotal_malicious,
                       ti.virustotal_suspicious,
                       ti.virustotal_is_malicious
                  FROM events e
                  LEFT JOIN threat_intel ti ON ti.event_id = e.id
                 WHERE e.id = ?
                """,
                (event_id,),
            ).fetchone()

        return _row_to_dict(row) if row else None

    def get_event_count(self) -> int:
        with self.connection() as conn:
            return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def get_unique_source_ips(self) -> int:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT COUNT(DISTINCT source_ip) FROM events WHERE source_ip IS NOT NULL AND source_ip != ''"
            ).fetchone()
            return row[0]

    # ── Threat intel ────────────────────────────────────────────────────

    def insert_threat_intel(self, event_id: int, threat_intel_data: dict[str, Any]) -> None:
        """Store enrichment results for an event."""
        providers = threat_intel_data.get("providers") or {}
        score = threat_intel_data.get("score") or {}

        abuse = providers.get("abuseipdb") or {}
        vt = providers.get("virustotal") or {}

        with self.connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO threat_intel (
                    event_id, source_ip, status,
                    abuseipdb_score, abuseipdb_is_malicious,
                    virustotal_malicious, virustotal_suspicious, virustotal_is_malicious,
                    combined_is_malicious, combined_confidence,
                    raw_result
                ) VALUES (
                    :event_id, :source_ip, :status,
                    :abuseipdb_score, :abuseipdb_is_malicious,
                    :virustotal_malicious, :virustotal_suspicious, :virustotal_is_malicious,
                    :combined_is_malicious, :combined_confidence,
                    :raw_result
                )
                """,
                {
                    "event_id": event_id,
                    "source_ip": threat_intel_data.get("lookup_ip", ""),
                    "status": threat_intel_data.get("status", "unknown"),
                    "abuseipdb_score": abuse.get("result", {}).get("abuse_confidence_score"),
                    "abuseipdb_is_malicious": 1 if abuse.get("is_malicious") else 0,
                    "virustotal_malicious": vt.get("result", {}).get("malicious"),
                    "virustotal_suspicious": vt.get("result", {}).get("suspicious"),
                    "virustotal_is_malicious": 1 if vt.get("is_malicious") else 0,
                    "combined_is_malicious": 1 if score.get("is_malicious") else 0,
                    "combined_confidence": score.get("confidence"),
                    "raw_result": json.dumps(threat_intel_data, ensure_ascii=True),
                },
            )
            conn.commit()

    # ── Attack sessions ─────────────────────────────────────────────────

    def upsert_attack_session(self, record: dict[str, Any]) -> None:
        """Create or update an attack session row from an event record."""
        session_id = record.get("session_id")
        source_ip = record.get("source_ip")
        if not session_id or not source_ip:
            return

        classification = record.get("classification") or {}
        category = classification.get("attack_category", "unknown")
        severity = classification.get("severity", "low")
        timestamp = record.get("timestamp") or ""
        threat_intel = record.get("threat_intel") or {}
        score = threat_intel.get("score") or {}
        is_malicious = 1 if score.get("is_malicious") else 0
        honeypot = record.get("honeypot", "cowrie")

        with self.connection() as conn:
            existing = conn.execute(
                "SELECT id, attack_categories, severity_counts, event_count, is_malicious, start_time "
                "FROM attack_sessions WHERE session_id = ? AND source_ip = ?",
                (session_id, source_ip),
            ).fetchone()

            if existing:
                cats = json.loads(existing["attack_categories"] or "[]")
                if category not in cats:
                    cats.append(category)

                sev = json.loads(existing["severity_counts"] or "{}")
                sev[severity] = sev.get(severity, 0) + 1

                new_count = existing["event_count"] + 1
                new_is_malicious = 1 if (existing["is_malicious"] or is_malicious) else 0
                risk = score_session_snapshot(
                    event_count=new_count,
                    attack_categories=cats,
                    severity_counts=sev,
                    is_malicious=bool(new_is_malicious),
                )

                # Keep earliest start_time
                start_time = existing["start_time"]
                if start_time and timestamp and timestamp < start_time:
                    start_time = timestamp
                elif not start_time:
                    start_time = timestamp

                conn.execute(
                    """
                    UPDATE attack_sessions
                       SET event_count       = ?,
                           attack_categories = ?,
                           severity_counts   = ?,
                           is_malicious      = ?,
                           risk_score        = ?,
                           risk_level        = ?,
                           risk_reasons      = ?,
                           start_time        = ?,
                           end_time          = ?,
                           last_seen         = datetime('now')
                     WHERE id = ?
                    """,
                    (
                        new_count,
                        json.dumps(cats, ensure_ascii=True),
                        json.dumps(sev, ensure_ascii=True),
                        new_is_malicious,
                        risk["score"],
                        risk["level"],
                        json.dumps(risk["reasons"], ensure_ascii=True),
                        start_time,
                        timestamp,
                        existing["id"],
                    ),
                )
            else:
                risk = score_session_snapshot(
                    event_count=1,
                    attack_categories=[category],
                    severity_counts={severity: 1},
                    is_malicious=bool(is_malicious),
                )
                conn.execute(
                    """
                    INSERT INTO attack_sessions (
                        session_id, source_ip, honeypot,
                        start_time, end_time, event_count,
                        attack_categories, severity_counts,
                        is_malicious, risk_score, risk_level, risk_reasons
                    ) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session_id,
                        source_ip,
                        honeypot,
                        timestamp,
                        timestamp,
                        json.dumps([category], ensure_ascii=True),
                        json.dumps({severity: 1}, ensure_ascii=True),
                        is_malicious,
                        risk["score"],
                        risk["level"],
                        json.dumps(risk["reasons"], ensure_ascii=True),
                    ),
                )
            conn.commit()

    def query_attack_sessions(
        self,
        source_ip: str | None = None,
        malicious_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        """Return attack sessions with filtering."""
        where: list[str] = []
        params: list[Any] = []

        if source_ip:
            where.append("source_ip LIKE ?")
            params.append(f"{source_ip}%")
        if malicious_only:
            where.append("is_malicious = 1")

        where_clause = " AND ".join(where) if where else "1=1"

        with self.connection() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) FROM attack_sessions WHERE {where_clause}", params
            ).fetchone()[0]

            rows = conn.execute(
                f"""
                SELECT * FROM attack_sessions
                 WHERE {where_clause}
                 ORDER BY last_seen DESC
                 LIMIT ? OFFSET ?
                """,
                params + [limit, offset],
            ).fetchall()

        results: list[dict[str, Any]] = []
        for r in rows:
            d = _row_to_dict(r)
            if d is None:
                continue
            d["attack_categories"] = json.loads(str(d.get("attack_categories", "[]")))
            d["severity_counts"] = json.loads(str(d.get("severity_counts", "{}")))
            if isinstance(d.get("risk_reasons"), str):
                d["risk_reasons"] = json.loads(str(d.get("risk_reasons", "[]")))
            elif not isinstance(d.get("risk_reasons"), list):
                d["risk_reasons"] = []
            results.append(d)

        return results, total

    def get_session_timeline(self, session_id: str, source_ip: str) -> list[dict[str, Any]]:
        """Return all events for a given attack session, chronologically."""
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM events
                 WHERE session_id = ? AND source_ip = ?
                 ORDER BY timestamp ASC
                """,
                (session_id, source_ip),
            ).fetchall()
        results: list[dict[str, Any]] = []
        for r in rows:
            d = _row_to_dict(r)
            if d is not None:
                results.append(d)
        return results

    # ── Summary statistics ──────────────────────────────────────────────

    def get_summary(self) -> dict[str, Any]:
        with self.connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            unique_ips = conn.execute(
                "SELECT COUNT(DISTINCT source_ip) FROM events WHERE source_ip IS NOT NULL AND source_ip != ''"
            ).fetchone()[0]
            malicious_count = conn.execute(
                "SELECT COUNT(*) FROM events WHERE is_malicious = 1"
            ).fetchone()[0]
            blocklist_count = conn.execute(
                "SELECT COUNT(*) FROM threat_intel WHERE combined_is_malicious = 1"
            ).fetchone()[0]

            categories = conn.execute(
                """
                SELECT attack_category, COUNT(*) as cnt
                  FROM events
                 WHERE attack_category IS NOT NULL
                 GROUP BY attack_category
                 ORDER BY cnt DESC
                """
            ).fetchall()

            event_types = conn.execute(
                """
                SELECT event_type, COUNT(*) as cnt
                  FROM events
                 GROUP BY event_type
                 ORDER BY cnt DESC
                """
            ).fetchall()

            protocols = conn.execute(
                """
                SELECT protocol, COUNT(*) as cnt
                  FROM events
                 WHERE protocol IS NOT NULL
                 GROUP BY protocol
                 ORDER BY cnt DESC
                """
            ).fetchall()

            risk_levels = conn.execute(
                """
                SELECT risk_level, COUNT(*) as cnt
                  FROM events
                 WHERE risk_level IS NOT NULL
                 GROUP BY risk_level
                 ORDER BY cnt DESC
                """
            ).fetchall()

        return {
            "total_events": total,
            "unique_source_ips": unique_ips,
            "malicious_event_count": malicious_count,
            "blocklist_count": blocklist_count,
            "by_attack_category": {r["attack_category"]: r["cnt"] for r in categories},
            "by_event_type": {r["event_type"]: r["cnt"] for r in event_types},
            "by_protocol": {r["protocol"]: r["cnt"] for r in protocols},
            "by_risk_level": {r["risk_level"]: r["cnt"] for r in risk_levels},
        }

    def get_top_threats(self, limit: int = 10) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT source_ip, COUNT(*) as cnt
                  FROM events
                 WHERE source_ip IS NOT NULL AND source_ip != ''
                 GROUP BY source_ip
                 ORDER BY cnt DESC
                 LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [{"ip": r["source_ip"], "count": r["cnt"]} for r in rows]

    def get_filter_options(self) -> dict[str, list[str]]:
        with self.connection() as conn:
            event_types = [
                r[0] for r in conn.execute(
                    "SELECT DISTINCT event_type FROM events WHERE event_type IS NOT NULL ORDER BY event_type"
                )
            ]
            attack_categories = [
                r[0] for r in conn.execute(
                    "SELECT DISTINCT attack_category FROM events WHERE attack_category IS NOT NULL ORDER BY attack_category"
                )
            ]
            protocols = [
                r[0] for r in conn.execute(
                    "SELECT DISTINCT protocol FROM events WHERE protocol IS NOT NULL ORDER BY protocol"
                )
            ]
        return {
            "event_types": event_types,
            "attack_categories": attack_categories,
            "protocols": protocols,
        }

    # ── Dashboard users and authentication ─────────────────────────────

    def create_user(
        self,
        *,
        email: str,
        password: str,
        first_name: str,
        middle_name: str | None,
        cloud_provider: str,
    ) -> dict[str, Any]:
        normalized_email = validate_email(email)
        first = first_name.strip()
        middle = middle_name.strip() if middle_name else None
        provider = validate_cloud_provider(cloud_provider)
        if not first:
            raise AuthError("First name is required.")

        user_id = self._new_user_id()
        password_digest = hash_password(password)
        try:
            with self.connection() as conn:
                conn.execute(
                    """
                    INSERT INTO users (
                        user_id, email, first_name, middle_name,
                        cloud_provider, password_hash
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (user_id, normalized_email, first, middle, provider, password_digest),
                )
                conn.commit()
        except sqlite3.IntegrityError as exc:
            if "users.email" in str(exc):
                raise AuthError("An account with this email already exists.") from exc
            if "users.user_id" in str(exc):
                return self.create_user(
                    email=email,
                    password=password,
                    first_name=first_name,
                    middle_name=middle_name,
                    cloud_provider=cloud_provider,
                )
            raise

        user = self.get_user_by_email(normalized_email)
        if user is None:
            raise RuntimeError("User creation succeeded but user could not be loaded.")
        return user

    def authenticate_user(self, email: str, password: str) -> dict[str, Any] | None:
        normalized_email = validate_email(email)
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE email = ?",
                (normalized_email,),
            ).fetchone()
        if row is None or not verify_password(password, row["password_hash"]):
            return None
        return public_user(dict(row))

    def create_session(self, user_id: str, days: int = 7) -> str:
        token = generate_token()
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO user_sessions (user_id, token_hash, expires_at)
                VALUES (?, ?, datetime('now', ?))
                """,
                (user_id, hash_token(token), f"+{days} days"),
            )
            conn.commit()
        return token

    def revoke_session(self, token: str) -> None:
        with self.connection() as conn:
            conn.execute(
                """
                UPDATE user_sessions
                   SET revoked_at = datetime('now')
                 WHERE token_hash = ?
                """,
                (hash_token(token),),
            )
            conn.commit()

    def get_user_by_session_token(self, token: str) -> dict[str, Any] | None:
        if not token:
            return None
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT u.*
                  FROM user_sessions s
                  JOIN users u ON u.user_id = s.user_id
                 WHERE s.token_hash = ?
                   AND s.revoked_at IS NULL
                   AND datetime(s.expires_at) > datetime('now')
                """,
                (hash_token(token),),
            ).fetchone()
        return public_user(dict(row)) if row else None

    def get_user_by_email(self, email: str) -> dict[str, Any] | None:
        normalized_email = validate_email(email)
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE email = ?",
                (normalized_email,),
            ).fetchone()
        return public_user(dict(row)) if row else None

    def create_password_reset_token(self, email: str, minutes: int = 30) -> str | None:
        normalized_email = validate_email(email)
        with self.connection() as conn:
            row = conn.execute(
                "SELECT user_id FROM users WHERE email = ?",
                (normalized_email,),
            ).fetchone()
            if row is None:
                return None
            token = generate_token()
            conn.execute(
                """
                UPDATE password_reset_tokens
                   SET used_at = datetime('now')
                 WHERE user_id = ? AND used_at IS NULL
                """,
                (row["user_id"],),
            )
            conn.execute(
                """
                INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
                VALUES (?, ?, datetime('now', ?))
                """,
                (row["user_id"], hash_token(token), f"+{minutes} minutes"),
            )
            conn.commit()
        return token

    def reset_password(self, token: str, new_password: str) -> bool:
        token_digest = hash_token(token)
        password_digest = hash_password(new_password)
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT id, user_id
                  FROM password_reset_tokens
                 WHERE token_hash = ?
                   AND used_at IS NULL
                   AND datetime(expires_at) > datetime('now')
                """,
                (token_digest,),
            ).fetchone()
            if row is None:
                return False

            conn.execute(
                """
                UPDATE users
                   SET password_hash = ?, updated_at = datetime('now')
                 WHERE user_id = ?
                """,
                (password_digest, row["user_id"]),
            )
            conn.execute(
                """
                UPDATE password_reset_tokens
                   SET used_at = datetime('now')
                 WHERE id = ?
                """,
                (row["id"],),
            )
            conn.execute(
                """
                UPDATE user_sessions
                   SET revoked_at = datetime('now')
                 WHERE user_id = ? AND revoked_at IS NULL
                """,
                (row["user_id"],),
            )
            conn.commit()
        return True

    def _new_user_id(self) -> str:
        return f"user_{uuid.uuid4().hex}"

    # ── Devices ─────────────────────────────────────────────────────────

    def create_device(
        self,
        *,
        user_id: str,
        name: str,
        provider: str | None,
    ) -> dict[str, Any]:
        """Enroll a device for *user_id*.

        Returns the public device record plus a one-time plaintext agent
        ``token``.  Only the token hash is stored.
        """
        device_name = name.strip()
        if not device_name:
            raise AuthError("Device name is required.")
        device_provider = provider.strip().lower() if provider and provider.strip() else None

        device_id = f"device_{uuid.uuid4().hex}"
        token = generate_token()
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO devices (device_id, user_id, name, provider, token_hash)
                VALUES (?, ?, ?, ?, ?)
                """,
                (device_id, user_id, device_name, device_provider, hash_token(token)),
            )
            conn.commit()

        return {
            "device_id": device_id,
            "name": device_name,
            "provider": device_provider,
            "hostname": None,
            "last_seen": None,
            "status": "offline",
            "metrics": {},
            "token": token,
        }

    def list_devices(self, user_id: str) -> list[dict[str, Any]]:
        """Return the user's devices with latest metrics and online state."""
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT device_id, name, provider, hostname, last_seen,
                       latest_metrics, created_at,
                       CASE
                         WHEN last_seen IS NULL THEN NULL
                         ELSE (julianday('now') - julianday(last_seen)) * 86400.0
                       END AS age_seconds
                  FROM devices
                 WHERE user_id = ?
                 ORDER BY created_at ASC
                """,
                (user_id,),
            ).fetchall()

        devices: list[dict[str, Any]] = []
        for row in rows:
            d = dict(row)
            age = d.pop("age_seconds")
            metrics_raw = d.pop("latest_metrics")
            try:
                d["metrics"] = json.loads(metrics_raw) if metrics_raw else {}
            except (json.JSONDecodeError, TypeError):
                d["metrics"] = {}
            d["status"] = _device_status(age)
            d["age_seconds"] = int(age) if age is not None else None
            devices.append(d)
        return devices

    def delete_device(self, user_id: str, device_id: str) -> bool:
        """Delete a device owned by *user_id*.  Returns True if a row was removed."""
        with self.connection() as conn:
            cursor = conn.execute(
                "DELETE FROM devices WHERE device_id = ? AND user_id = ?",
                (device_id, user_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def record_heartbeat(self, token: str, metrics: dict[str, Any]) -> str | None:
        """Update a device's latest metrics using its agent token.

        Returns the device id on success, or *None* if the token is invalid.
        Only whitelisted metric fields are persisted.
        """
        if not token:
            return None
        clean = _sanitize_metrics(metrics)
        hostname = clean.get("hostname")
        with self.connection() as conn:
            row = conn.execute(
                "SELECT device_id FROM devices WHERE token_hash = ?",
                (hash_token(token),),
            ).fetchone()
            if row is None:
                return None
            conn.execute(
                """
                UPDATE devices
                   SET latest_metrics = ?,
                       hostname       = COALESCE(?, hostname),
                       last_seen      = datetime('now')
                 WHERE device_id = ?
                """,
                (
                    json.dumps(clean, ensure_ascii=True),
                    hostname if isinstance(hostname, str) else None,
                    row["device_id"],
                ),
            )
            conn.commit()
            return row["device_id"]


# ── Helpers ────────────────────────────────────────────────────────────────


def _device_status(age_seconds: float | None) -> str:
    if age_seconds is None:
        return "offline"
    if age_seconds <= DEVICE_ONLINE_SECONDS:
        return "online"
    if age_seconds <= DEVICE_STALE_SECONDS:
        return "stale"
    return "offline"


def _sanitize_metrics(metrics: dict[str, Any]) -> dict[str, Any]:
    """Keep only known metric keys with primitive (str/int/float/bool) values.

    Agent heartbeats are untrusted; this prevents arbitrary nested or oversized
    data from being persisted, and nothing here is ever executed.
    """
    if not isinstance(metrics, dict):
        return {}
    clean: dict[str, Any] = {}
    for key in DEVICE_METRIC_KEYS:
        if key not in metrics:
            continue
        value = metrics[key]
        if isinstance(value, bool) or isinstance(value, (int, float)):
            clean[key] = value
        elif isinstance(value, str):
            clean[key] = value[:200]
    return clean


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    d = dict(row)

    # ── Reconstruct nested classification from flat columns ──────────
    attack_cat = d.pop("attack_category", None)
    severity = d.pop("severity", None)
    class_reason = d.pop("classification_reason", None)
    d["attack_category"] = attack_cat or "unknown"
    d["classification"] = {
        "attack_category": attack_cat or "unknown",
        "severity": severity or "low",
        "reason": class_reason or "",
        "target_profile": "server",
        "service_type": d.get("protocol") or "unknown",
    }

    # ── Reconstruct nested threat_intel from flat ti_* columns ──────
    ti_status = d.pop("ti_status", None)
    ti_confidence = d.pop("ti_confidence", None)
    ti_is_malicious = d.pop("ti_is_malicious", None)
    ti_raw = d.pop("ti_raw_result", None)
    abuse_score = d.pop("abuseipdb_score", None)
    abuse_mal = d.pop("abuseipdb_is_malicious", None)
    vt_mal = d.pop("virustotal_malicious", None)
    vt_sus = d.pop("virustotal_suspicious", None)
    vt_is_mal = d.pop("virustotal_is_malicious", None)

    if ti_status is not None:
        d["ti_status"] = ti_status
        d["ti_confidence"] = ti_confidence
        d["ti_is_malicious"] = ti_is_malicious
        d["abuseipdb_score"] = abuse_score
        d["virustotal_malicious"] = vt_mal
        d["virustotal_suspicious"] = vt_sus
        d["threat_intel"] = {
            "status": ti_status,
            "lookup_ip": d.get("source_ip"),
            "score": {
                "is_malicious": bool(ti_is_malicious),
                "confidence": ti_confidence or "low",
                "malicious_provider_count": (1 if abuse_mal else 0) + (1 if vt_is_mal else 0),
                "malicious_providers": [],
            },
            "providers": {
                "abuseipdb": {
                    "status": "completed",
                    "is_malicious": bool(abuse_mal),
                    "result": {"abuse_confidence_score": abuse_score},
                },
                "virustotal": {
                    "status": "completed",
                    "is_malicious": bool(vt_is_mal),
                    "result": {"malicious": vt_mal, "suspicious": vt_sus},
                },
            } if abuse_score is not None or vt_mal is not None else {},
            "raw_result": ti_raw,
        }
    else:
        d["threat_intel"] = None

    # ── Parse JSON fields ───────────────────────────────────────────
    for key in ("raw_event", "raw_result", "risk_reasons"):
        val = d.get(key)
        if isinstance(val, str):
            try:
                d[key] = json.loads(val)
            except json.JSONDecodeError:
                pass

    d["risk"] = {
        "score": d.get("risk_score") or 0,
        "level": d.get("risk_level") or "minimal",
        "reasons": d.get("risk_reasons") if isinstance(d.get("risk_reasons"), list) else [],
    }

    return d
