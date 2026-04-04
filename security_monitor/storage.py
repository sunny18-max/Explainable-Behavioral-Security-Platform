from __future__ import annotations

from collections import Counter
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from .models import (
    AlertRecord,
    AppObservation,
    BehaviorFeatures,
    BehaviorProfile,
    BrowserEvent,
    DetectionSignal,
    ProcessObservation,
)


class SQLiteRepository:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _apply_since_clause(
        query: str,
        parameters: list[object],
        column_name: str,
        since: datetime | None,
    ) -> str:
        if since is None:
            return query
        parameters.append(since.isoformat())
        return f"{query} AND {column_name} >= ?"

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS behavior_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    observed_at TEXT NOT NULL,
                    source TEXT NOT NULL,
                    typing_speed REAL NOT NULL,
                    typing_gap_variance REAL NOT NULL,
                    mouse_speed REAL NOT NULL,
                    app_switch_count INTEGER NOT NULL,
                    unique_app_count INTEGER NOT NULL,
                    dominant_app TEXT NOT NULL,
                    apps_seen TEXT NOT NULL,
                    login_hour REAL NOT NULL,
                    session_duration_minutes REAL NOT NULL,
                    activity_intensity REAL NOT NULL,
                    keystroke_count INTEGER NOT NULL,
                    mouse_event_count INTEGER NOT NULL,
                    risk_score REAL NOT NULL,
                    severity TEXT NOT NULL,
                    is_anomaly INTEGER NOT NULL,
                    baseline_eligible INTEGER NOT NULL,
                    summary TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    confidence_score REAL NOT NULL DEFAULT 0,
                    fingerprint_similarity REAL,
                    behavior_drift REAL,
                    scenario_name TEXT,
                    expected_anomaly INTEGER,
                    replay_summary TEXT NOT NULL DEFAULT '',
                    risk_factors TEXT NOT NULL DEFAULT '[]',
                    recommended_actions TEXT NOT NULL DEFAULT '[]',
                    watchlist_hits TEXT NOT NULL DEFAULT '[]',
                    domain_categories TEXT NOT NULL DEFAULT '[]',
                    intent_matches TEXT NOT NULL DEFAULT '[]',
                    timeline TEXT NOT NULL DEFAULT '[]',
                    app_observations TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    summary TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    feedback_label TEXT,
                    feedback_note TEXT,
                    recommended_actions TEXT NOT NULL DEFAULT '[]',
                    cluster_key TEXT NOT NULL DEFAULT 'general',
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS browser_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    observed_at TEXT NOT NULL,
                    browser_name TEXT NOT NULL,
                    tab_title TEXT NOT NULL,
                    url TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    search_query TEXT,
                    source TEXT NOT NULL,
                    tab_id INTEGER,
                    window_id INTEGER,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS behavior_daily_rollups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    day_key TEXT NOT NULL,
                    sample_count INTEGER NOT NULL,
                    anomaly_count INTEGER NOT NULL,
                    average_risk REAL NOT NULL,
                    peak_risk REAL NOT NULL,
                    average_confidence REAL NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(user_id, day_key),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS browser_daily_rollups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    day_key TEXT NOT NULL,
                    event_count INTEGER NOT NULL,
                    query_event_count INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(user_id, day_key),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );

                CREATE INDEX IF NOT EXISTS idx_behavior_logs_user_observed_at
                    ON behavior_logs(user_id, observed_at);

                CREATE INDEX IF NOT EXISTS idx_browser_events_user_observed_at
                    ON browser_events(user_id, observed_at);

                CREATE INDEX IF NOT EXISTS idx_behavior_daily_rollups_user_day
                    ON behavior_daily_rollups(user_id, day_key);

                CREATE INDEX IF NOT EXISTS idx_browser_daily_rollups_user_day
                    ON browser_daily_rollups(user_id, day_key);

                CREATE INDEX IF NOT EXISTS idx_alerts_user_created_at
                    ON alerts(user_id, created_at);

                CREATE TABLE IF NOT EXISTS baseline_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    captured_at TEXT NOT NULL,
                    sample_count INTEGER NOT NULL,
                    feedback_offset REAL NOT NULL DEFAULT 0,
                    baselines_json TEXT NOT NULL,
                    known_apps_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );

                CREATE INDEX IF NOT EXISTS idx_baseline_snapshots_user_captured_at
                    ON baseline_snapshots(user_id, captured_at);

                CREATE TABLE IF NOT EXISTS integration_exports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    target_kind TEXT NOT NULL,
                    target_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    file_path TEXT,
                    webhook_url TEXT,
                    error_message TEXT,
                    payload_json TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );

                CREATE INDEX IF NOT EXISTS idx_integration_exports_user_created_at
                    ON integration_exports(user_id, created_at);
                """
            )
            self._ensure_column(
                connection,
                "behavior_logs",
                "app_observations",
                "TEXT NOT NULL DEFAULT '[]'",
            )
            self._ensure_column(
                connection,
                "behavior_logs",
                "confidence_score",
                "REAL NOT NULL DEFAULT 0",
            )
            self._ensure_column(
                connection,
                "behavior_logs",
                "fingerprint_similarity",
                "REAL",
            )
            self._ensure_column(
                connection,
                "behavior_logs",
                "behavior_drift",
                "REAL",
            )
            self._ensure_column(
                connection,
                "behavior_logs",
                "intent_matches",
                "TEXT NOT NULL DEFAULT '[]'",
            )
            self._ensure_column(
                connection,
                "behavior_logs",
                "timeline",
                "TEXT NOT NULL DEFAULT '[]'",
            )
            self._ensure_column(
                connection,
                "behavior_logs",
                "scenario_name",
                "TEXT",
            )
            self._ensure_column(
                connection,
                "behavior_logs",
                "expected_anomaly",
                "INTEGER",
            )
            self._ensure_column(
                connection,
                "behavior_logs",
                "replay_summary",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column(
                connection,
                "behavior_logs",
                "risk_factors",
                "TEXT NOT NULL DEFAULT '[]'",
            )
            self._ensure_column(
                connection,
                "behavior_logs",
                "recommended_actions",
                "TEXT NOT NULL DEFAULT '[]'",
            )
            self._ensure_column(
                connection,
                "behavior_logs",
                "watchlist_hits",
                "TEXT NOT NULL DEFAULT '[]'",
            )
            self._ensure_column(
                connection,
                "behavior_logs",
                "domain_categories",
                "TEXT NOT NULL DEFAULT '[]'",
            )
            self._ensure_column(
                connection,
                "behavior_logs",
                "process_observations",
                "TEXT NOT NULL DEFAULT '[]'",
            )
            self._ensure_column(
                connection,
                "behavior_logs",
                "honeypot_hits",
                "TEXT NOT NULL DEFAULT '[]'",
            )
            self._ensure_column(
                connection,
                "alerts",
                "feedback_label",
                "TEXT",
            )
            self._ensure_column(
                connection,
                "alerts",
                "feedback_note",
                "TEXT",
            )
            self._ensure_column(
                connection,
                "alerts",
                "recommended_actions",
                "TEXT NOT NULL DEFAULT '[]'",
            )
            self._ensure_column(
                connection,
                "alerts",
                "cluster_key",
                "TEXT NOT NULL DEFAULT 'general'",
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_alerts_cluster_key
                    ON alerts(user_id, cluster_key)
                """
            )

    def _ensure_column(
        self,
        connection: sqlite3.Connection,
        table_name: str,
        column_name: str,
        column_definition: str,
    ) -> None:
        columns = {
            str(row["name"])
            for row in connection.execute(f"PRAGMA table_info({table_name})").fetchall()
        }
        if column_name in columns:
            return
        connection.execute(
            f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}"
        )

    def get_or_create_user_record(self, username: str) -> tuple[int, str]:
        normalized = username.strip()
        created_at = datetime.now().isoformat()
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT id, username FROM users WHERE LOWER(username) = LOWER(?)",
                (normalized,),
            ).fetchone()
            if existing:
                return int(existing["id"]), str(existing["username"])

            cursor = connection.execute(
                "INSERT INTO users(username, created_at) VALUES (?, ?)",
                (normalized, created_at),
            )
            return int(cursor.lastrowid), normalized

    def get_or_create_user(self, username: str) -> int:
        return self.get_or_create_user_record(username)[0]

    def list_users(self) -> list[str]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT username FROM users ORDER BY username"
            ).fetchall()
        return [str(row["username"]) for row in rows]

    def save_behavior_sample(
        self,
        user_id: int,
        features: BehaviorFeatures,
        detection: DetectionSignal,
        baseline_eligible: bool,
        fingerprint_similarity: float | None = None,
        behavior_drift: float | None = None,
        timeline: list[dict[str, str]] | None = None,
        scenario_name: str | None = None,
        expected_anomaly: bool | None = None,
        replay_summary: str = "",
        risk_factors: list[dict[str, object]] | None = None,
        recommended_actions: list[str] | None = None,
        watchlist_hits: list[str] | None = None,
        domain_categories: list[str] | None = None,
        cluster_key: str = "general",
    ) -> None:
        payload = features.as_record()
        created_at = datetime.now().isoformat()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO behavior_logs (
                    user_id, observed_at, source, typing_speed,
                    typing_gap_variance, mouse_speed, app_switch_count,
                    unique_app_count, dominant_app, apps_seen,
                    login_hour, session_duration_minutes, activity_intensity,
                    keystroke_count, mouse_event_count, risk_score,
                    severity, is_anomaly, baseline_eligible, summary,
                    explanation, confidence_score, fingerprint_similarity, behavior_drift,
                    scenario_name, expected_anomaly, replay_summary, risk_factors,
                    recommended_actions, watchlist_hits, domain_categories,
                    intent_matches, timeline, app_observations, process_observations,
                    honeypot_hits, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    payload["observed_at"],
                    payload["source"],
                    payload["typing_speed"],
                    payload["typing_gap_variance"],
                    payload["mouse_speed"],
                    payload["app_switch_count"],
                    payload["unique_app_count"],
                    payload["dominant_app"],
                    json.dumps(payload["apps_seen"]),
                    payload["login_hour"],
                    payload["session_duration_minutes"],
                    payload["activity_intensity"],
                    payload["keystroke_count"],
                    payload["mouse_event_count"],
                    detection.risk_score,
                    detection.severity,
                    int(detection.is_anomaly),
                    int(baseline_eligible),
                    detection.summary,
                    detection.explanation,
                    detection.confidence_score,
                    fingerprint_similarity,
                    behavior_drift,
                    scenario_name,
                    int(expected_anomaly) if expected_anomaly is not None else None,
                    replay_summary,
                    json.dumps(risk_factors or []),
                    json.dumps(recommended_actions or []),
                    json.dumps(watchlist_hits or []),
                    json.dumps(domain_categories or []),
                    json.dumps(detection.intent_matches),
                    json.dumps(timeline or []),
                    json.dumps(payload["app_observations"]),
                    json.dumps(payload["process_observations"]),
                    json.dumps(payload["honeypot_hits"]),
                    created_at,
                ),
            )

            if detection.is_anomaly:
                connection.execute(
                    """
                    INSERT INTO alerts (
                        user_id, created_at, severity, risk_score, summary, explanation,
                        recommended_actions, cluster_key
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        user_id,
                        created_at,
                        detection.severity,
                        detection.risk_score,
                        detection.summary,
                        detection.explanation,
                        json.dumps(recommended_actions or detection.recommended_actions),
                        cluster_key or detection.cluster_key or "general",
                    ),
                )

    def save_browser_events(self, user_id: int, events: list[BrowserEvent]) -> int:
        if not events:
            return 0

        created_at = datetime.now().isoformat()
        rows = [
            (
                user_id,
                event.observed_at.isoformat(),
                event.browser_name,
                event.tab_title,
                event.url,
                event.domain,
                event.search_query,
                event.source,
                event.tab_id,
                event.window_id,
                created_at,
            )
            for event in events
        ]
        with self._connect() as connection:
            connection.executemany(
                """
                INSERT INTO browser_events (
                    user_id, observed_at, browser_name, tab_title, url, domain,
                    search_query, source, tab_id, window_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        return len(rows)

    def load_recent_samples(
        self,
        user_id: int,
        limit: int,
        baseline_only: bool = False,
        since: datetime | None = None,
    ) -> list[BehaviorFeatures]:
        query = """
            SELECT observed_at, typing_speed, typing_gap_variance, mouse_speed,
                   app_switch_count, unique_app_count, dominant_app, apps_seen,
                   login_hour, session_duration_minutes, activity_intensity,
                   keystroke_count, mouse_event_count, app_observations,
                   process_observations, honeypot_hits, source
            FROM behavior_logs
            WHERE user_id = ?
        """
        parameters: list[object] = [user_id]
        if baseline_only:
            query += " AND baseline_eligible = 1"
        query = self._apply_since_clause(query, parameters, "observed_at", since)
        query += " ORDER BY observed_at DESC LIMIT ?"
        parameters.append(limit)

        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()

        return [self._row_to_features(row) for row in reversed(rows)]

    def load_recent_alerts(
        self,
        user_id: int,
        limit: int = 10,
        since: datetime | None = None,
    ) -> list[AlertRecord]:
        query = """
                SELECT a.id, a.created_at, a.severity, a.risk_score, a.summary,
                       a.explanation, a.feedback_label, a.feedback_note,
                       a.recommended_actions, a.cluster_key, u.username
                FROM alerts AS a
                JOIN users AS u ON u.id = a.user_id
                WHERE a.user_id = ?
        """
        parameters: list[object] = [user_id]
        query = self._apply_since_clause(query, parameters, "a.created_at", since)
        query += " ORDER BY a.created_at DESC LIMIT ?"
        parameters.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()

        return [
            AlertRecord(
                id=int(row["id"]),
                created_at=datetime.fromisoformat(str(row["created_at"])),
                severity=str(row["severity"]),
                risk_score=float(row["risk_score"]),
                summary=str(row["summary"]),
                explanation=str(row["explanation"]),
                user_name=str(row["username"]),
                feedback_label=(
                    str(row["feedback_label"])
                    if row["feedback_label"] is not None
                    else None
                ),
                feedback_note=(
                    str(row["feedback_note"])
                    if row["feedback_note"] is not None
                    else None
                ),
                recommended_actions=list(
                    json.loads(str(row["recommended_actions"] or "[]"))
                ),
                cluster_key=str(row["cluster_key"] or "general"),
            )
            for row in rows
        ]

    def load_browser_events_between(
        self,
        user_id: int,
        started_at: datetime,
        ended_at: datetime,
    ) -> list[BrowserEvent]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT observed_at, browser_name, tab_title, url, domain,
                       search_query, source, tab_id, window_id
                FROM browser_events
                WHERE user_id = ?
                  AND observed_at >= ?
                  AND observed_at <= ?
                ORDER BY observed_at ASC
                """,
                (user_id, started_at.isoformat(), ended_at.isoformat()),
            ).fetchall()

        return [
            BrowserEvent(
                observed_at=datetime.fromisoformat(str(row["observed_at"])),
                browser_name=str(row["browser_name"]),
                tab_title=str(row["tab_title"]),
                url=str(row["url"]),
                domain=str(row["domain"]),
                search_query=(
                    str(row["search_query"])
                    if row["search_query"] is not None
                    else None
                ),
                source=str(row["source"]),
                tab_id=int(row["tab_id"]) if row["tab_id"] is not None else None,
                window_id=(
                    int(row["window_id"]) if row["window_id"] is not None else None
                ),
            )
            for row in rows
        ]

    def load_recent_telemetry(
        self,
        user_id: int,
        limit: int,
        since: datetime | None = None,
    ) -> list[dict[str, object]]:
        query = """
                SELECT observed_at, typing_speed, mouse_speed, risk_score,
                       severity, dominant_app, source, is_anomaly, confidence_score,
                       fingerprint_similarity, behavior_drift
                FROM behavior_logs
                WHERE user_id = ?
        """
        parameters: list[object] = [user_id]
        query = self._apply_since_clause(query, parameters, "observed_at", since)
        query += " ORDER BY observed_at DESC LIMIT ?"
        parameters.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()

        return [
            {
                "observed_at": str(row["observed_at"]),
                "typing_speed": float(row["typing_speed"]),
                "mouse_speed": float(row["mouse_speed"]),
                "risk_score": float(row["risk_score"]),
                "severity": str(row["severity"]),
                "dominant_app": str(row["dominant_app"]),
                "source": str(row["source"]),
                "is_anomaly": bool(int(row["is_anomaly"])),
                "confidence_score": float(row["confidence_score"]),
                "fingerprint_similarity": (
                    float(row["fingerprint_similarity"])
                    if row["fingerprint_similarity"] is not None
                    else None
                ),
                "behavior_drift": (
                    float(row["behavior_drift"])
                    if row["behavior_drift"] is not None
                    else None
                ),
            }
            for row in reversed(rows)
        ]

    def load_overview_metrics(
        self,
        user_id: int,
        since: datetime | None = None,
    ) -> dict[str, float | int]:
        behavior_query = """
                SELECT COUNT(*) AS total_samples,
                       COALESCE(SUM(CASE WHEN baseline_eligible = 1 THEN 1 ELSE 0 END), 0) AS baseline_samples,
                       COALESCE(SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END), 0) AS anomaly_count,
                       COALESCE(SUM(CASE WHEN honeypot_hits != '[]' THEN 1 ELSE 0 END), 0) AS honeypot_detection_count,
                       COALESCE(AVG(risk_score), 0) AS average_risk,
                       COALESCE(AVG(confidence_score), 0) AS average_confidence,
                       COALESCE(AVG(fingerprint_similarity), 0) AS average_fingerprint_similarity,
                       COALESCE(AVG(behavior_drift), 0) AS average_behavior_drift,
                       COALESCE(MAX(risk_score), 0) AS peak_risk,
                       COUNT(DISTINCT dominant_app) AS distinct_apps
                FROM behavior_logs
                WHERE user_id = ?
        """
        browser_query = """
                SELECT COUNT(*) AS browser_event_count,
                       MAX(observed_at) AS last_browser_event_at,
                       COUNT(DISTINCT domain) AS distinct_domains
                FROM browser_events
                WHERE user_id = ?
        """
        export_query = """
                SELECT COUNT(*) AS integration_export_count,
                       MAX(created_at) AS last_integration_export_at
                FROM integration_exports
                WHERE user_id = ?
        """
        behavior_parameters: list[object] = [user_id]
        browser_parameters: list[object] = [user_id]
        export_parameters: list[object] = [user_id]
        behavior_query = self._apply_since_clause(behavior_query, behavior_parameters, "observed_at", since)
        browser_query = self._apply_since_clause(browser_query, browser_parameters, "observed_at", since)
        export_query = self._apply_since_clause(export_query, export_parameters, "created_at", since)
        with self._connect() as connection:
            behavior_row = connection.execute(behavior_query, behavior_parameters).fetchone()
            browser_row = connection.execute(browser_query, browser_parameters).fetchone()
            export_row = connection.execute(export_query, export_parameters).fetchone()

        return {
            "total_samples": int(behavior_row["total_samples"]),
            "baseline_samples": int(behavior_row["baseline_samples"]),
            "anomaly_count": int(behavior_row["anomaly_count"]),
            "honeypot_detection_count": int(behavior_row["honeypot_detection_count"]),
            "average_risk": round(float(behavior_row["average_risk"]), 2),
            "average_confidence": round(float(behavior_row["average_confidence"]), 2),
            "average_fingerprint_similarity": round(
                float(behavior_row["average_fingerprint_similarity"]),
                2,
            ),
            "average_behavior_drift": round(
                float(behavior_row["average_behavior_drift"]),
                2,
            ),
            "peak_risk": round(float(behavior_row["peak_risk"]), 2),
            "distinct_apps": int(behavior_row["distinct_apps"]),
            "browser_event_count": int(browser_row["browser_event_count"]),
            "last_browser_event_at": (
                str(browser_row["last_browser_event_at"])
                if browser_row["last_browser_event_at"] is not None
                else None
            ),
            "distinct_domains": int(browser_row["distinct_domains"]),
            "integration_export_count": int(export_row["integration_export_count"]),
            "last_integration_export_at": (
                str(export_row["last_integration_export_at"])
                if export_row["last_integration_export_at"] is not None
                else None
            ),
        }

    def load_governance_metrics(self, user_id: int) -> dict[str, object]:
        with self._connect() as connection:
            raw_behavior_row = connection.execute(
                """
                SELECT COUNT(*) AS raw_behavior_samples,
                       MIN(observed_at) AS oldest_behavior_sample
                FROM behavior_logs
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()
            raw_browser_row = connection.execute(
                """
                SELECT COUNT(*) AS raw_browser_events,
                       MIN(observed_at) AS oldest_browser_event
                FROM browser_events
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()
            behavior_rollup_row = connection.execute(
                """
                SELECT COUNT(*) AS archived_behavior_days,
                       COALESCE(SUM(sample_count), 0) AS archived_behavior_samples
                FROM behavior_daily_rollups
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()
            browser_rollup_row = connection.execute(
                """
                SELECT COUNT(*) AS archived_browser_days,
                       COALESCE(SUM(event_count), 0) AS archived_browser_events
                FROM browser_daily_rollups
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()

        return {
            "raw_behavior_samples": int(raw_behavior_row["raw_behavior_samples"]),
            "raw_browser_events": int(raw_browser_row["raw_browser_events"]),
            "archived_behavior_days": int(behavior_rollup_row["archived_behavior_days"]),
            "archived_behavior_samples": int(behavior_rollup_row["archived_behavior_samples"]),
            "archived_browser_days": int(browser_rollup_row["archived_browser_days"]),
            "archived_browser_events": int(browser_rollup_row["archived_browser_events"]),
            "oldest_behavior_sample": (
                str(raw_behavior_row["oldest_behavior_sample"])
                if raw_behavior_row["oldest_behavior_sample"] is not None
                else None
            ),
            "oldest_browser_event": (
                str(raw_browser_row["oldest_browser_event"])
                if raw_browser_row["oldest_browser_event"] is not None
                else None
            ),
        }

    def record_integration_export(
        self,
        user_id: int,
        target_kind: str,
        target_name: str,
        status: str,
        payload: dict[str, object],
        file_path: str | None = None,
        webhook_url: str | None = None,
        error_message: str | None = None,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO integration_exports (
                    user_id, created_at, target_kind, target_name, status,
                    file_path, webhook_url, error_message, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    datetime.now().isoformat(),
                    target_kind,
                    target_name,
                    status,
                    file_path,
                    webhook_url,
                    error_message,
                    json.dumps(payload),
                ),
            )

    def load_recent_integration_exports(
        self,
        user_id: int,
        limit: int = 8,
        since: datetime | None = None,
    ) -> list[dict[str, object]]:
        query = """
                SELECT created_at, target_kind, target_name, status, file_path,
                       webhook_url, error_message
                FROM integration_exports
                WHERE user_id = ?
        """
        parameters: list[object] = [user_id]
        query = self._apply_since_clause(query, parameters, "created_at", since)
        query += " ORDER BY created_at DESC LIMIT ?"
        parameters.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()

        return [
            {
                "created_at": str(row["created_at"]),
                "target_kind": str(row["target_kind"]),
                "target_name": str(row["target_name"]),
                "status": str(row["status"]),
                "file_path": str(row["file_path"]) if row["file_path"] is not None else None,
                "webhook_url": (
                    str(row["webhook_url"]) if row["webhook_url"] is not None else None
                ),
                "error_message": (
                    str(row["error_message"]) if row["error_message"] is not None else None
                ),
            }
            for row in rows
        ]

    def apply_retention_policy(
        self,
        behavior_retention_days: int,
        browser_retention_days: int,
    ) -> dict[str, int]:
        behavior_cutoff = (
            datetime.now() - timedelta(days=max(int(behavior_retention_days), 0))
        ).isoformat()
        browser_cutoff = (
            datetime.now() - timedelta(days=max(int(browser_retention_days), 0))
        ).isoformat()
        with self._connect() as connection:
            behavior_count = int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM behavior_logs
                    WHERE observed_at < ?
                    """,
                    (behavior_cutoff,),
                ).fetchone()[0]
            )
            browser_count = int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM browser_events
                    WHERE observed_at < ?
                    """,
                    (browser_cutoff,),
                ).fetchone()[0]
            )

            if behavior_count:
                connection.execute(
                    """
                    INSERT INTO behavior_daily_rollups (
                        user_id, day_key, sample_count, anomaly_count,
                        average_risk, peak_risk, average_confidence, created_at
                    )
                    SELECT
                        user_id,
                        substr(observed_at, 1, 10) AS day_key,
                        COUNT(*) AS sample_count,
                        SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) AS anomaly_count,
                        AVG(risk_score) AS average_risk,
                        MAX(risk_score) AS peak_risk,
                        AVG(confidence_score) AS average_confidence,
                        ?
                    FROM behavior_logs
                    WHERE observed_at < ?
                    GROUP BY user_id, substr(observed_at, 1, 10)
                    ON CONFLICT(user_id, day_key) DO UPDATE SET
                        sample_count = behavior_daily_rollups.sample_count + excluded.sample_count,
                        anomaly_count = behavior_daily_rollups.anomaly_count + excluded.anomaly_count,
                        average_risk = (
                            (behavior_daily_rollups.average_risk * behavior_daily_rollups.sample_count) +
                            (excluded.average_risk * excluded.sample_count)
                        ) / (behavior_daily_rollups.sample_count + excluded.sample_count),
                        peak_risk = MAX(behavior_daily_rollups.peak_risk, excluded.peak_risk),
                        average_confidence = (
                            (behavior_daily_rollups.average_confidence * behavior_daily_rollups.sample_count) +
                            (excluded.average_confidence * excluded.sample_count)
                        ) / (behavior_daily_rollups.sample_count + excluded.sample_count),
                        created_at = excluded.created_at
                    """,
                    (
                        datetime.now().isoformat(),
                        behavior_cutoff,
                    ),
                )
                connection.execute(
                    """
                    DELETE FROM behavior_logs
                    WHERE observed_at < ?
                    """,
                    (behavior_cutoff,),
                )

            if browser_count:
                connection.execute(
                    """
                    INSERT INTO browser_daily_rollups (
                        user_id, day_key, event_count, query_event_count, created_at
                    )
                    SELECT
                        user_id,
                        substr(observed_at, 1, 10) AS day_key,
                        COUNT(*) AS event_count,
                        SUM(CASE WHEN search_query IS NOT NULL AND TRIM(search_query) != '' THEN 1 ELSE 0 END) AS query_event_count,
                        ?
                    FROM browser_events
                    WHERE observed_at < ?
                    GROUP BY user_id, substr(observed_at, 1, 10)
                    ON CONFLICT(user_id, day_key) DO UPDATE SET
                        event_count = browser_daily_rollups.event_count + excluded.event_count,
                        query_event_count = browser_daily_rollups.query_event_count + excluded.query_event_count,
                        created_at = excluded.created_at
                    """,
                    (
                        datetime.now().isoformat(),
                        browser_cutoff,
                    ),
                )
                connection.execute(
                    """
                    DELETE FROM browser_events
                    WHERE observed_at < ?
                    """,
                    (browser_cutoff,),
                )

        return {
            "archived_behavior_samples": behavior_count,
            "archived_browser_events": browser_count,
        }

    def load_app_distribution(
        self,
        user_id: int,
        limit: int = 6,
        since: datetime | None = None,
    ) -> list[dict[str, object]]:
        query = """
                SELECT dominant_app, COUNT(*) AS samples
                FROM behavior_logs
                WHERE user_id = ?
        """
        parameters: list[object] = [user_id]
        query = self._apply_since_clause(query, parameters, "observed_at", since)
        query += " GROUP BY dominant_app ORDER BY samples DESC, dominant_app ASC LIMIT ?"
        parameters.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()

        return [
            {
                "label": str(row["dominant_app"]),
                "value": int(row["samples"]),
            }
            for row in rows
        ]

    def load_severity_distribution(
        self,
        user_id: int,
        since: datetime | None = None,
    ) -> list[dict[str, object]]:
        query = """
                SELECT severity, COUNT(*) AS samples
                FROM behavior_logs
                WHERE user_id = ?
        """
        parameters: list[object] = [user_id]
        query = self._apply_since_clause(query, parameters, "observed_at", since)
        query += " GROUP BY severity ORDER BY samples DESC, severity ASC"
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()

        return [
            {
                "label": str(row["severity"]),
                "value": int(row["samples"]),
            }
            for row in rows
        ]

    def load_recent_browser_activity(
        self,
        user_id: int,
        limit: int = 20,
        since: datetime | None = None,
    ) -> list[dict[str, object]]:
        query = """
                SELECT observed_at, browser_name, tab_title, url, domain, search_query, source
                FROM browser_events
                WHERE user_id = ?
        """
        parameters: list[object] = [user_id]
        query = self._apply_since_clause(query, parameters, "observed_at", since)
        query += " ORDER BY observed_at DESC LIMIT ?"
        parameters.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()

        if not rows:
            return self._load_recent_browser_activity_from_behavior_logs(user_id, limit, since=since)

        return [
            {
                "observed_at": str(row["observed_at"]),
                "app_name": str(row["browser_name"]),
                "window_title": str(row["tab_title"]),
                "tab_title": str(row["tab_title"]),
                "search_query": (
                    str(row["search_query"]) if row["search_query"] is not None else None
                ),
                "url": str(row["url"]),
                "domain": str(row["domain"]),
                "source": str(row["source"]),
            }
            for row in rows
        ]

    def load_query_distribution(
        self,
        user_id: int,
        limit: int = 6,
        since: datetime | None = None,
    ) -> list[dict[str, object]]:
        query = """
                SELECT search_query, COUNT(*) AS uses
                FROM browser_events
                WHERE user_id = ?
                  AND search_query IS NOT NULL
                  AND TRIM(search_query) != ''
        """
        parameters: list[object] = [user_id]
        query = self._apply_since_clause(query, parameters, "observed_at", since)
        query += " GROUP BY search_query ORDER BY uses DESC, search_query ASC LIMIT ?"
        parameters.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()

        if not rows:
            return self._load_query_distribution_from_behavior_logs(user_id, limit, since=since)

        return [
            {
                "label": str(row["search_query"]),
                "value": int(row["uses"]),
            }
            for row in rows
        ]

    def load_domain_distribution(
        self,
        user_id: int,
        limit: int = 6,
        since: datetime | None = None,
    ) -> list[dict[str, object]]:
        query = """
                SELECT domain, COUNT(*) AS uses
                FROM browser_events
                WHERE user_id = ?
                  AND domain != ''
        """
        parameters: list[object] = [user_id]
        query = self._apply_since_clause(query, parameters, "observed_at", since)
        query += " GROUP BY domain ORDER BY uses DESC, domain ASC LIMIT ?"
        parameters.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()

        return [
            {
                "label": str(row["domain"]),
                "value": int(row["uses"]),
            }
            for row in rows
        ]

    def load_user_comparison(self) -> list[dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT u.id, u.username,
                       COUNT(b.id) AS total_samples,
                       COALESCE(SUM(CASE WHEN b.is_anomaly = 1 THEN 1 ELSE 0 END), 0) AS anomaly_count,
                       COALESCE(AVG(b.risk_score), 0) AS average_risk,
                       COALESCE(AVG(b.confidence_score), 0) AS average_confidence,
                       COALESCE(AVG(b.fingerprint_similarity), 0) AS average_fingerprint_similarity,
                       COALESCE(MAX(b.risk_score), 0) AS peak_risk,
                       MAX(b.observed_at) AS last_seen
                FROM users AS u
                LEFT JOIN behavior_logs AS b ON b.user_id = u.id
                GROUP BY u.id, u.username
                ORDER BY average_risk DESC, anomaly_count DESC, u.username ASC
                """
            ).fetchall()

            comparison: list[dict[str, object]] = []
            for row in rows:
                user_id = int(row["id"])
                top_apps = connection.execute(
                    """
                    SELECT dominant_app, COUNT(*) AS samples
                    FROM behavior_logs
                    WHERE user_id = ?
                    GROUP BY dominant_app
                    ORDER BY samples DESC, dominant_app ASC
                    LIMIT 3
                    """,
                    (user_id,),
                ).fetchall()

                comparison.append(
                    {
                        "user_name": str(row["username"]),
                        "total_samples": int(row["total_samples"]),
                        "anomaly_count": int(row["anomaly_count"]),
                        "average_risk": round(float(row["average_risk"]), 2),
                        "average_confidence": round(float(row["average_confidence"]), 2),
                        "average_fingerprint_similarity": round(
                            float(row["average_fingerprint_similarity"]),
                            2,
                        ),
                        "peak_risk": round(float(row["peak_risk"]), 2),
                        "last_seen": str(row["last_seen"]) if row["last_seen"] else None,
                        "top_apps": [str(app_row["dominant_app"]) for app_row in top_apps],
                        "browser_event_count": int(
                            connection.execute(
                                "SELECT COUNT(*) FROM browser_events WHERE user_id = ?",
                                (user_id,),
                            ).fetchone()[0]
                        ),
                    }
                )

        return comparison

    def set_alert_feedback(self, alert_id: int, label: str, note: str = "") -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE alerts
                SET feedback_label = ?, feedback_note = ?
                WHERE id = ?
                """,
                (label, note or None, alert_id),
            )

    def load_feedback_summary(
        self,
        user_id: int,
        since: datetime | None = None,
    ) -> dict[str, float | int]:
        query = """
                SELECT COUNT(*) AS total_alerts,
                       COALESCE(SUM(CASE WHEN feedback_label = 'true_positive' THEN 1 ELSE 0 END), 0) AS true_positive_count,
                       COALESCE(SUM(CASE WHEN feedback_label = 'false_positive' THEN 1 ELSE 0 END), 0) AS false_positive_count,
                       COALESCE(SUM(CASE WHEN feedback_label = 'needs_review' THEN 1 ELSE 0 END), 0) AS needs_review_count
                FROM alerts
                WHERE user_id = ?
        """
        parameters: list[object] = [user_id]
        query = self._apply_since_clause(query, parameters, "created_at", since)
        with self._connect() as connection:
            row = connection.execute(query, parameters).fetchone()

        true_positive_count = int(row["true_positive_count"])
        false_positive_count = int(row["false_positive_count"])
        needs_review_count = int(row["needs_review_count"])
        total_alerts = int(row["total_alerts"])
        reviewed_count = true_positive_count + false_positive_count + needs_review_count
        return {
            "total_alerts": total_alerts,
            "reviewed_alerts": reviewed_count,
            "true_positive_count": true_positive_count,
            "false_positive_count": false_positive_count,
            "needs_review_count": needs_review_count,
            "unreviewed_alert_count": max(total_alerts - reviewed_count, 0),
            "adaptive_threshold_offset": self.load_feedback_adjustment(user_id, since=since),
        }

    def load_feedback_adjustment(
        self,
        user_id: int,
        limit: int = 24,
        since: datetime | None = None,
    ) -> float:
        query = """
                SELECT feedback_label
                FROM alerts
                WHERE user_id = ?
                  AND feedback_label IS NOT NULL
        """
        parameters: list[object] = [user_id]
        query = self._apply_since_clause(query, parameters, "created_at", since)
        query += " ORDER BY created_at DESC LIMIT ?"
        parameters.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()

        if not rows:
            return 0.0

        labels = [str(row["feedback_label"]) for row in rows]
        false_positive_count = labels.count("false_positive")
        true_positive_count = labels.count("true_positive")
        adjustment = min(false_positive_count * 2.0, 12.0) - min(true_positive_count * 1.0, 6.0)
        return round(adjustment, 1)

    def save_baseline_snapshot(
        self,
        user_id: int,
        profile: BehaviorProfile,
        captured_at: datetime,
        feedback_offset: float,
    ) -> None:
        baselines_json = json.dumps(
            {
                key: {
                    "mean": value.mean,
                    "median": value.median,
                    "stdev": value.stdev,
                    "lower_bound": value.lower_bound,
                    "upper_bound": value.upper_bound,
                }
                for key, value in profile.baselines.items()
            }
        )
        known_apps_json = json.dumps(sorted(profile.known_apps))
        with self._connect() as connection:
            latest = connection.execute(
                """
                SELECT sample_count, feedback_offset
                FROM baseline_snapshots
                WHERE user_id = ?
                ORDER BY captured_at DESC
                LIMIT 1
                """,
                (user_id,),
            ).fetchone()
            if latest is not None:
                if (
                    int(latest["sample_count"]) == profile.sample_count
                    and round(float(latest["feedback_offset"] or 0.0), 1) == round(feedback_offset, 1)
                ):
                    return

            connection.execute(
                """
                INSERT INTO baseline_snapshots (
                    user_id, captured_at, sample_count, feedback_offset,
                    baselines_json, known_apps_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    captured_at.isoformat(),
                    profile.sample_count,
                    feedback_offset,
                    baselines_json,
                    known_apps_json,
                    datetime.now().isoformat(),
                ),
            )

    def load_baseline_versions(
        self,
        user_id: int,
        limit: int = 6,
        since: datetime | None = None,
    ) -> list[dict[str, object]]:
        query = """
                SELECT captured_at, sample_count, feedback_offset, baselines_json
                FROM baseline_snapshots
                WHERE user_id = ?
        """
        parameters: list[object] = [user_id]
        query = self._apply_since_clause(query, parameters, "captured_at", since)
        query += " ORDER BY captured_at DESC LIMIT ?"
        parameters.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()

        versions: list[dict[str, object]] = []
        for row in reversed(rows):
            baselines = json.loads(str(row["baselines_json"] or "{}"))
            versions.append(
                {
                    "captured_at": str(row["captured_at"]),
                    "sample_count": int(row["sample_count"]),
                    "feedback_offset": float(row["feedback_offset"]),
                    "typing_speed": round(float(baselines.get("typing_speed", {}).get("mean", 0.0)), 2),
                    "mouse_speed": round(float(baselines.get("mouse_speed", {}).get("mean", 0.0)), 2),
                    "login_hour": round(float(baselines.get("login_hour", {}).get("mean", 0.0)), 2),
                }
            )
        return versions

    def load_domain_category_distribution(
        self,
        user_id: int,
        limit: int = 6,
        since: datetime | None = None,
    ) -> list[dict[str, object]]:
        counter: Counter[str] = Counter()
        query = """
                SELECT domain
                FROM browser_events
                WHERE user_id = ?
                  AND TRIM(domain) != ''
        """
        parameters: list[object] = [user_id]
        query = self._apply_since_clause(query, parameters, "observed_at", since)
        query += " ORDER BY observed_at DESC LIMIT 250"
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()

        if rows:
            for row in rows:
                category = self._domain_category(str(row["domain"]))
                if category:
                    counter[category] += 1
        else:
            with self._connect() as connection:
                behavior_rows = connection.execute(
                    """
                    SELECT domain_categories
                    FROM behavior_logs
                    WHERE user_id = ?
                    """ + (" AND observed_at >= ?" if since is not None else "") + """
                    ORDER BY observed_at DESC
                    LIMIT 120
                    """,
                    ((user_id, since.isoformat()) if since is not None else (user_id,)),
                ).fetchall()
            for row in behavior_rows:
                for category in json.loads(str(row["domain_categories"] or "[]")):
                    counter[str(category)] += 1

        return [
            {"label": label, "value": value}
            for label, value in counter.most_common(limit)
        ]

    def load_alert_clusters(
        self,
        user_id: int,
        limit: int = 6,
        since: datetime | None = None,
    ) -> list[dict[str, object]]:
        query = """
                SELECT id, cluster_key, summary, severity, feedback_label, created_at
                FROM alerts
                WHERE user_id = ?
        """
        parameters: list[object] = [user_id]
        query = self._apply_since_clause(query, parameters, "created_at", since)
        query += " ORDER BY created_at DESC LIMIT 120"
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()

        clusters: dict[str, dict[str, object]] = {}
        for row in rows:
            key = str(row["cluster_key"] or "general")
            if key not in clusters:
                clusters[key] = {
                    "cluster_key": key,
                    "count": 0,
                    "latest_summary": str(row["summary"]),
                    "latest_severity": str(row["severity"]),
                    "true_positive_count": 0,
                    "false_positive_count": 0,
                    "needs_review_count": 0,
                    "last_seen": str(row["created_at"]),
                }
            cluster = clusters[key]
            cluster["count"] = int(cluster["count"]) + 1
            feedback_label = row["feedback_label"]
            if feedback_label:
                counter_key = f"{feedback_label}_count"
                cluster[counter_key] = int(cluster.get(counter_key, 0)) + 1

        ordered = sorted(
            clusters.values(),
            key=lambda item: (-int(item["count"]), str(item["cluster_key"])),
        )
        return ordered[:limit]

    def load_risk_heatmap(
        self,
        user_id: int,
        since: datetime | None = None,
    ) -> list[dict[str, object]]:
        query = """
                SELECT CAST(strftime('%H', observed_at) AS INTEGER) AS hour_bin,
                       COALESCE(AVG(risk_score), 0) AS average_risk,
                       COALESCE(SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END), 0) AS alert_count,
                       COUNT(*) AS samples
                FROM behavior_logs
                WHERE user_id = ?
        """
        parameters: list[object] = [user_id]
        query = self._apply_since_clause(query, parameters, "observed_at", since)
        query += " GROUP BY hour_bin ORDER BY hour_bin ASC"
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()

        row_map = {int(row["hour_bin"]): row for row in rows}
        heatmap: list[dict[str, object]] = []
        for hour in range(24):
            row = row_map.get(hour)
            heatmap.append(
                {
                    "hour": hour,
                    "average_risk": round(float(row["average_risk"]), 1) if row else 0.0,
                    "alert_count": int(row["alert_count"]) if row else 0,
                    "samples": int(row["samples"]) if row else 0,
                }
            )
        return heatmap

    def load_demo_evaluation(self, user_id: int) -> dict[str, object]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT scenario_name, expected_anomaly, is_anomaly
                FROM behavior_logs
                WHERE user_id = ?
                  AND source = 'demo'
                  AND expected_anomaly IS NOT NULL
                ORDER BY observed_at DESC
                LIMIT 240
                """,
                (user_id,),
            ).fetchall()

        if not rows:
            return {
                "sample_count": 0,
                "accuracy": 0.0,
                "precision": 0.0,
                "recall": 0.0,
                "true_positive": 0,
                "false_positive": 0,
                "true_negative": 0,
                "false_negative": 0,
                "scenario_breakdown": [],
            }

        true_positive = false_positive = true_negative = false_negative = 0
        scenario_counter: Counter[str] = Counter()
        for row in rows:
            expected = bool(int(row["expected_anomaly"]))
            predicted = bool(int(row["is_anomaly"]))
            scenario_counter[str(row["scenario_name"] or "unspecified")] += 1
            if expected and predicted:
                true_positive += 1
            elif not expected and predicted:
                false_positive += 1
            elif expected and not predicted:
                false_negative += 1
            else:
                true_negative += 1

        sample_count = len(rows)
        accuracy = (true_positive + true_negative) / sample_count if sample_count else 0.0
        precision = true_positive / (true_positive + false_positive) if (true_positive + false_positive) else 0.0
        recall = true_positive / (true_positive + false_negative) if (true_positive + false_negative) else 0.0

        return {
            "sample_count": sample_count,
            "accuracy": round(accuracy * 100.0, 1),
            "precision": round(precision * 100.0, 1),
            "recall": round(recall * 100.0, 1),
            "true_positive": true_positive,
            "false_positive": false_positive,
            "true_negative": true_negative,
            "false_negative": false_negative,
            "scenario_breakdown": [
                {"label": label, "value": value}
                for label, value in scenario_counter.most_common(6)
            ],
        }

    def _load_recent_browser_activity_from_behavior_logs(
        self,
        user_id: int,
        limit: int,
        since: datetime | None = None,
    ) -> list[dict[str, object]]:
        query = """
                SELECT observed_at, app_observations
                FROM behavior_logs
                WHERE user_id = ?
        """
        parameters: list[object] = [user_id]
        query = self._apply_since_clause(query, parameters, "observed_at", since)
        query += " ORDER BY observed_at DESC LIMIT ?"
        parameters.append(max(limit, 10))
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()

        browser_rows: list[dict[str, object]] = []
        for row in rows:
            observed_at = str(row["observed_at"])
            observations = json.loads(str(row["app_observations"] or "[]"))
            for observation in observations:
                tab_title = observation.get("tab_title")
                search_query = observation.get("search_query")
                if not tab_title and not search_query:
                    continue
                browser_rows.append(
                    {
                        "observed_at": observed_at,
                        "app_name": observation.get("app_name", ""),
                        "window_title": observation.get("window_title", ""),
                        "tab_title": tab_title,
                        "search_query": search_query,
                        "url": observation.get("url", ""),
                        "domain": observation.get("domain", ""),
                        "source": observation.get("source", "system"),
                    }
                )
                if len(browser_rows) >= limit:
                    return browser_rows
        return browser_rows

    def _load_query_distribution_from_behavior_logs(
        self,
        user_id: int,
        limit: int,
        since: datetime | None = None,
    ) -> list[dict[str, object]]:
        query_counter: dict[str, int] = {}
        query = """
                SELECT app_observations
                FROM behavior_logs
                WHERE user_id = ?
        """
        parameters: list[object] = [user_id]
        query = self._apply_since_clause(query, parameters, "observed_at", since)
        query += " ORDER BY observed_at DESC LIMIT 120"
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()

        for row in rows:
            observations = json.loads(str(row["app_observations"] or "[]"))
            for observation in observations:
                query = str(observation.get("search_query") or "").strip()
                if not query:
                    continue
                query_counter[query] = query_counter.get(query, 0) + 1

        ordered = sorted(query_counter.items(), key=lambda item: (-item[1], item[0]))
        return [
            {
                "label": query,
                "value": count,
            }
            for query, count in ordered[:limit]
        ]

    @staticmethod
    def _domain_category(domain: str) -> str:
        cleaned = domain.strip().lower()
        if cleaned.startswith("www."):
            cleaned = cleaned[4:]
        if not cleaned:
            return ""
        search_domains = ("google.com", "bing.com", "duckduckgo.com", "search.brave.com", "yahoo.com")
        work_domains = ("office.com", "sharepoint.com", "teams.microsoft.com", "outlook.office.com", "notion.so", "atlassian.net")
        social_domains = ("youtube.com", "linkedin.com", "reddit.com", "x.com", "twitter.com", "instagram.com", "facebook.com")
        admin_domains = ("learn.microsoft.com", "docs.microsoft.com", "github.com", "stackoverflow.com")
        if any(cleaned == item or cleaned.endswith(f".{item}") for item in search_domains):
            return "search"
        if any(cleaned == item or cleaned.endswith(f".{item}") for item in work_domains):
            return "work"
        if any(cleaned == item or cleaned.endswith(f".{item}") for item in social_domains):
            return "social"
        if any(cleaned == item or cleaned.endswith(f".{item}") for item in admin_domains):
            return "admin_reference"
        return "unknown"

    @staticmethod
    def _row_to_features(row: sqlite3.Row) -> BehaviorFeatures:
        return BehaviorFeatures(
            observed_at=datetime.fromisoformat(str(row["observed_at"])),
            typing_speed=float(row["typing_speed"]),
            typing_gap_variance=float(row["typing_gap_variance"]),
            mouse_speed=float(row["mouse_speed"]),
            app_switch_count=int(row["app_switch_count"]),
            unique_app_count=int(row["unique_app_count"]),
            dominant_app=str(row["dominant_app"]),
            apps_seen=list(json.loads(str(row["apps_seen"]))),
            login_hour=float(row["login_hour"]),
            session_duration_minutes=float(row["session_duration_minutes"]),
            activity_intensity=float(row["activity_intensity"]),
            keystroke_count=int(row["keystroke_count"]),
            mouse_event_count=int(row["mouse_event_count"]),
            app_observations=[
                AppObservation(
                    app_name=str(observation.get("app_name", "")),
                    window_title=str(observation.get("window_title", "")),
                    tab_title=(
                        str(observation.get("tab_title"))
                        if observation.get("tab_title") is not None
                        else None
                    ),
                    search_query=(
                        str(observation.get("search_query"))
                        if observation.get("search_query") is not None
                        else None
                    ),
                    url=(
                        str(observation.get("url"))
                        if observation.get("url") is not None
                        else None
                    ),
                    domain=(
                        str(observation.get("domain"))
                        if observation.get("domain") is not None
                        else None
                    ),
                    source=str(observation.get("source", "system")),
                )
                for observation in json.loads(str(row["app_observations"] or "[]"))
            ],
            process_observations=[
                ProcessObservation(
                    observed_at=datetime.fromisoformat(
                        str(observation.get("observed_at", row["observed_at"]))
                    ),
                    process_name=str(observation.get("process_name", "")),
                    pid=(
                        int(observation["pid"])
                        if observation.get("pid") is not None
                        else None
                    ),
                    parent_name=(
                        str(observation.get("parent_name"))
                        if observation.get("parent_name") is not None
                        else None
                    ),
                    parent_pid=(
                        int(observation["parent_pid"])
                        if observation.get("parent_pid") is not None
                        else None
                    ),
                    ancestry=[
                        str(item)
                        for item in observation.get("ancestry", [])
                        if item is not None
                    ],
                    exe_path=(
                        str(observation.get("exe_path"))
                        if observation.get("exe_path") is not None
                        else None
                    ),
                    window_title=(
                        str(observation.get("window_title"))
                        if observation.get("window_title") is not None
                        else None
                    ),
                    source=str(observation.get("source", "system")),
                )
                for observation in json.loads(str(row["process_observations"] or "[]"))
            ],
            honeypot_hits=[
                str(item) for item in json.loads(str(row["honeypot_hits"] or "[]"))
            ],
            source=str(row["source"]),
        )
