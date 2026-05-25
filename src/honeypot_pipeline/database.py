"""Persistent SQLite storage for honeypot events, threat intel, and attack sessions.

Uses WAL mode for concurrent read/write. Schema is designed to be trivially
portable to PostgreSQL when needed.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

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
        created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_events_timestamp       ON events(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_events_source_ip       ON events(source_ip)",
    "CREATE INDEX IF NOT EXISTS idx_events_event_type       ON events(event_type)",
    "CREATE INDEX IF NOT EXISTS idx_events_session_id       ON events(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_attack_category  ON events(attack_category)",
    "CREATE INDEX IF NOT EXISTS idx_events_is_malicious     ON events(is_malicious)",
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
        first_seen        TEXT    NOT NULL DEFAULT (datetime('now')),
        last_seen         TEXT    NOT NULL DEFAULT (datetime('now')),
        UNIQUE(session_id, source_ip)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_attack_sessions_source_ip    ON attack_sessions(source_ip)",
    "CREATE INDEX IF NOT EXISTS idx_attack_sessions_session_id   ON attack_sessions(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_attack_sessions_is_malicious ON attack_sessions(is_malicious)",
    "CREATE INDEX IF NOT EXISTS idx_attack_sessions_last_seen    ON attack_sessions(last_seen)",
]

DEDUP_WINDOW_SECONDS = 60

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
            conn.commit()

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
                    is_malicious
                ) VALUES (
                    :timestamp, :event_type, :honeypot,
                    :source_ip, :source_port, :destination_ip, :destination_port,
                    :protocol, :session_id, :username, :password, :command, :url,
                    :raw_event, :attack_category, :severity, :classification_reason,
                    :is_malicious
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
            where.append("e.source_ip = ?")
            params.append(source_ip)
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
                        start_time,
                        timestamp,
                        existing["id"],
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO attack_sessions (
                        session_id, source_ip, honeypot,
                        start_time, end_time, event_count,
                        attack_categories, severity_counts,
                        is_malicious
                    ) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
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
            where.append("source_ip = ?")
            params.append(source_ip)
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

        return {
            "total_events": total,
            "unique_source_ips": unique_ips,
            "malicious_event_count": malicious_count,
            "blocklist_count": blocklist_count,
            "by_attack_category": {r["attack_category"]: r["cnt"] for r in categories},
            "by_event_type": {r["event_type"]: r["cnt"] for r in event_types},
            "by_protocol": {r["protocol"]: r["cnt"] for r in protocols},
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


# ── Helpers ────────────────────────────────────────────────────────────────


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    d = dict(row)

    # ── Reconstruct nested classification from flat columns ──────────
    attack_cat = d.pop("attack_category", None)
    severity = d.pop("severity", None)
    class_reason = d.pop("classification_reason", None)
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
    for key in ("raw_event", "raw_result"):
        val = d.get(key)
        if isinstance(val, str):
            try:
                d[key] = json.loads(val)
            except json.JSONDecodeError:
                pass

    return d
