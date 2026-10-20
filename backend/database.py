"""
SystemAuditor Enterprise — Warstwa Trwałego Składowania (Storage Layer)
=======================================================================
Obsługuje:
1. Trwałą lokalną bazę SQLite w trybie WAL (Write-Ahead Logging) z natywnymi kolumnami JSON,
   działającą od ręki (Zero-Config) na każdej stacji roboczej.
2. Pełny produkcyjny schemat DDL dla PostgreSQL 16 + TimescaleDB (Hypertables + GIN JSONB)
   zapisany również w `schema_timescaledb.sql` i dostępny z poziomu API/GUI.
3. Rejestr Nonce (Anti-Replay), Rate-Limiting oraz kwarantannę raportów podejrzanych o Poisoning.
"""

import datetime
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional


class AuditDatabase:
    """Wielowątkowa warstwa dostępu do bazy danych audytów, agentów i alertów bezpieczeństwa."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._get_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    os_family TEXT NOT NULL,
                    os_release TEXT NOT NULL,
                    architecture TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    is_elevated INTEGER NOT NULL DEFAULT 0,
                    policy_version TEXT NOT NULL,
                    cert_serial TEXT,
                    cert_expires_at TEXT,
                    status TEXT NOT NULL DEFAULT 'ONLINE', -- ONLINE, OFFLINE, QUARANTINED, REVOKED
                    last_heartbeat_utc TEXT NOT NULL,
                    last_audit_utc TEXT,
                    current_score REAL DEFAULT 0.0,
                    pass_count INTEGER DEFAULT 0,
                    fail_count INTEGER DEFAULT 0,
                    cpu_usage_pct REAL DEFAULT 0.0,
                    mem_rss_mb REAL DEFAULT 0.0,
                    boot_id TEXT
                );

                CREATE TABLE IF NOT EXISTS audit_reports (
                    report_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    os_family TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    submitted_at_utc TEXT NOT NULL,
                    ingested_at_utc TEXT NOT NULL,
                    posture_score REAL NOT NULL,
                    pass_count INTEGER NOT NULL,
                    fail_count INTEGER NOT NULL,
                    error_count INTEGER NOT NULL,
                    na_count INTEGER NOT NULL,
                    is_quarantined INTEGER NOT NULL DEFAULT 0,
                    anomaly_risk_score INTEGER NOT NULL DEFAULT 0,
                    anomaly_findings_json TEXT NOT NULL DEFAULT '[]',
                    evaluated_results_json TEXT NOT NULL,
                    raw_payload_json TEXT NOT NULL,
                    FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
                );

                CREATE INDEX IF NOT EXISTS idx_audit_reports_agent_time
                    ON audit_reports(agent_id, ingested_at_utc DESC);

                CREATE TABLE IF NOT EXISTS security_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_utc TEXT NOT NULL,
                    severity TEXT NOT NULL, -- CRITICAL, HIGH, WARNING, INFO
                    event_type TEXT NOT NULL, -- POISONING_ATTEMPT, REPLAY_BLOCKED, CERT_ISSUED, AGENT_QUARANTINED
                    agent_id TEXT,
                    title TEXT NOT NULL,
                    details TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS used_nonces (
                    nonce TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    seen_at_utc TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    full_name TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'SOC_ANALYST', -- SUPER_ADMIN, SOC_ANALYST, AUDITOR_READONLY
                    password_hash TEXT NOT NULL,
                    mfa_enabled INTEGER NOT NULL DEFAULT 1,
                    mfa_secret TEXT NOT NULL,
                    is_builtin INTEGER NOT NULL DEFAULT 0,
                    must_change_password INTEGER NOT NULL DEFAULT 0,
                    created_at_utc TEXT NOT NULL,
                    last_login_utc TEXT
                );

                CREATE TABLE IF NOT EXISTS alert_webhooks (
                    channel_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    provider TEXT NOT NULL, -- SLACK, TEAMS, DISCORD, SIEM_HTTP
                    target_url TEXT NOT NULL,
                    min_severity TEXT NOT NULL DEFAULT 'HIGH', -- CRITICAL, HIGH, WARNING, ALL
                    score_threshold REAL NOT NULL DEFAULT 70.0,
                    trigger_on_drift INTEGER NOT NULL DEFAULT 1,
                    trigger_on_poisoning INTEGER NOT NULL DEFAULT 1,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at_utc TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS alert_deliveries (
                    delivery_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_utc TEXT NOT NULL,
                    channel_id TEXT NOT NULL,
                    channel_name TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    event_trigger TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    agent_id TEXT,
                    delivery_status TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                """
            )
            # Migracja dla istniejącej bazy SQLite (dodanie kolumn is_builtin oraz must_change_password)
            existing_cols = {
                row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()
            }
            if "is_builtin" not in existing_cols:
                conn.execute("ALTER TABLE users ADD COLUMN is_builtin INTEGER NOT NULL DEFAULT 0")
            if "must_change_password" not in existing_cols:
                conn.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")

    def check_and_record_nonce(self, nonce: str, agent_id: str) -> bool:
        """
        Sprawdza, czy identyfikator `X-Request-Nonce` był już użyty (ochrona Anti-Replay).
        Zwraca True, jeśli nonce jest świeży i poprawny; False jeśli to powtórzony pakiet (Replay).
        """
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._lock, self._get_conn() as conn:
            row = conn.execute("SELECT nonce FROM used_nonces WHERE nonce = ?", (nonce,)).fetchone()
            if row is not None:
                return False
            conn.execute(
                "INSERT INTO used_nonces (nonce, agent_id, seen_at_utc) VALUES (?, ?, ?)",
                (nonce, agent_id, now),
            )
            return True

    def upsert_agent_registration(
        self,
        agent_id: str,
        hostname: str,
        os_family: str,
        os_release: str,
        architecture: str,
        ip_address: str,
        policy_version: str,
        cert_serial: str,
        cert_expires_at: str,
    ) -> None:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._lock, self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO agents (
                    agent_id, hostname, os_family, os_release, architecture,
                    ip_address, is_elevated, policy_version, cert_serial,
                    cert_expires_at, status, last_heartbeat_utc
                ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, 'ONLINE', ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    hostname=excluded.hostname,
                    os_family=excluded.os_family,
                    os_release=excluded.os_release,
                    architecture=excluded.architecture,
                    ip_address=excluded.ip_address,
                    policy_version=excluded.policy_version,
                    cert_serial=excluded.cert_serial,
                    cert_expires_at=excluded.cert_expires_at,
                    last_heartbeat_utc=excluded.last_heartbeat_utc
                """,
                (
                    agent_id,
                    hostname,
                    os_family,
                    os_release,
                    architecture,
                    ip_address,
                    policy_version,
                    cert_serial,
                    cert_expires_at,
                    now,
                ),
            )

    def update_heartbeat(
        self,
        agent_id: str,
        cpu_usage_pct: float,
        mem_rss_mb: float,
        policy_version: str,
        ip_address: str,
    ) -> Optional[Dict[str, Any]]:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._lock, self._get_conn() as conn:
            row = conn.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
            if not row:
                return None
            new_status = row["status"] if row["status"] in ("QUARANTINED", "REVOKED") else "ONLINE"
            conn.execute(
                """
                UPDATE agents
                SET last_heartbeat_utc = ?, cpu_usage_pct = ?, mem_rss_mb = ?,
                    policy_version = ?, ip_address = ?, status = ?
                WHERE agent_id = ?
                """,
                (now, cpu_usage_pct, mem_rss_mb, policy_version, ip_address, new_status, agent_id),
            )
            return dict(row)

    def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._get_conn() as conn:
            row = conn.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
            return dict(row) if row else None

    def list_agents(self) -> List[Dict[str, Any]]:
        with self._lock, self._get_conn() as conn:
            rows = conn.execute("SELECT * FROM agents ORDER BY current_score ASC, hostname ASC").fetchall()
            return [dict(r) for r in rows]

    def set_agent_status(self, agent_id: str, status: str) -> bool:
        with self._lock, self._get_conn() as conn:
            cur = conn.execute("UPDATE agents SET status = ? WHERE agent_id = ?", (status, agent_id))
            return cur.rowcount > 0

    def store_audit_report(
        self,
        report_id: str,
        agent_id: str,
        hostname: str,
        os_family: str,
        os_release: str,
        architecture: str,
        ip_address: str,
        is_elevated: bool,
        policy_version: str,
        submitted_at_utc: str,
        posture_score: float,
        counts: Dict[str, int],
        is_quarantined: bool,
        anomaly_risk_score: int,
        anomaly_findings: List[str],
        evaluated_results: List[Dict[str, Any]],
        raw_payload: Dict[str, Any],
        boot_id: Optional[str] = None,
    ) -> None:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._lock, self._get_conn() as conn:
            # Upewnij się, że agent istnieje w tabeli agents
            existing = conn.execute(
                "SELECT status, current_score FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()

            agent_status = "QUARANTINED" if is_quarantined else "ONLINE"
            if existing and existing["status"] == "REVOKED":
                agent_status = "REVOKED"

            # Jeśli raport jest poddany kwarantannie (Poisoning Attempt), NIE nadpisujemy dobrego wyniku hosta!
            if not existing:
                conn.execute(
                    """
                    INSERT INTO agents (
                        agent_id, hostname, os_family, os_release, architecture,
                        ip_address, is_elevated, policy_version, status,
                        last_heartbeat_utc, last_audit_utc, current_score,
                        pass_count, fail_count, boot_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        agent_id,
                        hostname,
                        os_family,
                        os_release,
                        architecture,
                        ip_address,
                        1 if is_elevated else 0,
                        policy_version,
                        agent_status,
                        now,
                        now,
                        posture_score if not is_quarantined else 0.0,
                        counts.get("PASS", 0),
                        counts.get("FAIL", 0),
                        boot_id,
                    ),
                )
            else:
                if is_quarantined:
                    conn.execute(
                        "UPDATE agents SET status = 'QUARANTINED', last_heartbeat_utc = ? WHERE agent_id = ?",
                        (now, agent_id),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE agents
                        SET hostname = ?, os_family = ?, os_release = ?, architecture = ?,
                            is_elevated = ?, policy_version = ?, status = ?,
                            last_heartbeat_utc = ?, last_audit_utc = ?,
                            current_score = ?, pass_count = ?, fail_count = ?,
                            boot_id = COALESCE(?, boot_id)
                        WHERE agent_id = ?
                        """,
                        (
                            hostname,
                            os_family,
                            os_release,
                            architecture,
                            1 if is_elevated else 0,
                            policy_version,
                            agent_status,
                            now,
                            now,
                            posture_score,
                            counts.get("PASS", 0),
                            counts.get("FAIL", 0),
                            boot_id,
                            agent_id,
                        ),
                    )

            # Zapisz sam raport w niemodyfikowalnym dzienniku (Append-Only Ledger)
            conn.execute(
                """
                INSERT INTO audit_reports (
                    report_id, agent_id, hostname, os_family, policy_version,
                    submitted_at_utc, ingested_at_utc, posture_score,
                    pass_count, fail_count, error_count, na_count,
                    is_quarantined, anomaly_risk_score, anomaly_findings_json,
                    evaluated_results_json, raw_payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report_id,
                    agent_id,
                    hostname,
                    os_family,
                    policy_version,
                    submitted_at_utc,
                    now,
                    posture_score,
                    counts.get("PASS", 0),
                    counts.get("FAIL", 0),
                    counts.get("ERROR", 0),
                    counts.get("NOT_APPLICABLE", 0),
                    1 if is_quarantined else 0,
                    anomaly_risk_score,
                    json.dumps(anomaly_findings, ensure_ascii=False),
                    json.dumps(evaluated_results, ensure_ascii=False),
                    json.dumps(raw_payload, ensure_ascii=False),
                ),
            )

    def log_security_event(
        self, severity: str, event_type: str, title: str, details: str, agent_id: Optional[str] = None
    ) -> None:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._lock, self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO security_events (timestamp_utc, severity, event_type, agent_id, title, details)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (now, severity, event_type, agent_id, title, details),
            )

    def get_latest_report_for_agent(self, agent_id: str, include_quarantined: bool = False) -> Optional[Dict[str, Any]]:
        with self._lock, self._get_conn() as conn:
            query = "SELECT * FROM audit_reports WHERE agent_id = ?"
            if not include_quarantined:
                query += " AND is_quarantined = 0"
            query += " ORDER BY ingested_at_utc DESC LIMIT 1"
            row = conn.execute(query, (agent_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            d["anomaly_findings"] = json.loads(d.pop("anomaly_findings_json", "[]"))
            d["evaluated_results"] = json.loads(d.pop("evaluated_results_json", "[]"))
            d["raw_payload"] = json.loads(d.pop("raw_payload_json", "{}"))
            return d

    def list_recent_reports(self, limit: int = 30) -> List[Dict[str, Any]]:
        with self._lock, self._get_conn() as conn:
            rows = conn.execute(
                """
                SELECT report_id, agent_id, hostname, os_family, policy_version,
                       submitted_at_utc, ingested_at_utc, posture_score,
                       pass_count, fail_count, error_count, na_count,
                       is_quarantined, anomaly_risk_score, anomaly_findings_json
                FROM audit_reports
                ORDER BY ingested_at_utc DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            result = []
            for r in rows:
                d = dict(r)
                d["anomaly_findings"] = json.loads(d.pop("anomaly_findings_json", "[]"))
                result.append(d)
            return result

    def list_security_events(self, limit: int = 40) -> List[Dict[str, Any]]:
        with self._lock, self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM security_events ORDER BY event_id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    def purge_simulated_nodes(self) -> int:
        """Usuwa wszystkie demonstracyjne/symulowane hosty, zostawiając wyłącznie prawdziwe maszyny."""
        demo_ids = (
            "agt-prod-ubuntu-db01",
            "agt-dmz-debian-gw02",
            "agt-win-dc01-ad",
            "agt-win-legacy-erp04",
            "agt-e2e-test-node",
        )
        placeholders = ",".join("?" for _ in demo_ids)
        with self._lock, self._get_conn() as conn:
            conn.execute(f"DELETE FROM audit_reports WHERE agent_id IN ({placeholders})", demo_ids)
            conn.execute(f"DELETE FROM security_events WHERE agent_id IN ({placeholders})", demo_ids)
            cur = conn.execute(f"DELETE FROM agents WHERE agent_id IN ({placeholders})", demo_ids)
            return cur.rowcount

    def delete_agent(self, agent_id: str) -> bool:
        """Usuwa wybranego agenta wraz z jego raportami."""
        with self._lock, self._get_conn() as conn:
            conn.execute("DELETE FROM audit_reports WHERE agent_id = ?", (agent_id,))
            conn.execute("DELETE FROM security_events WHERE agent_id = ?", (agent_id,))
            cur = conn.execute("DELETE FROM agents WHERE agent_id = ?", (agent_id,))
            return cur.rowcount > 0

    def list_reports_for_agent(self, agent_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Zwraca historię ostatnich raportów audytowych dla konkretnego endpointu."""
        with self._lock, self._get_conn() as conn:
            rows = conn.execute(
                """
                SELECT report_id, agent_id, hostname, os_family, policy_version,
                       submitted_at_utc, ingested_at_utc, posture_score,
                       pass_count, fail_count, error_count, na_count,
                       is_quarantined, anomaly_risk_score, anomaly_findings_json
                FROM audit_reports
                WHERE agent_id = ?
                ORDER BY ingested_at_utc DESC
                LIMIT ?
                """,
                (agent_id, limit),
            ).fetchall()
            result = []
            for r in rows:
                d = dict(r)
                d["anomaly_findings"] = json.loads(d.pop("anomaly_findings_json", "[]"))
                result.append(d)
            return result

    # -----------------------------------------------------------------
    # ZARZĄDZANIE UŻYTKOWNIKAMI I MFA (IAM / RBAC)
    # -----------------------------------------------------------------

    def create_user(
        self,
        user_id: str,
        username: str,
        full_name: str,
        role: str,
        password_hash: str,
        mfa_enabled: bool,
        mfa_secret: str,
        is_builtin: bool = False,
        must_change_password: bool = False,
    ) -> Dict[str, Any]:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._lock, self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO users (
                    user_id, username, full_name, role, password_hash,
                    mfa_enabled, mfa_secret, is_builtin, must_change_password, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    username.strip().lower(),
                    full_name.strip(),
                    role,
                    password_hash,
                    1 if mfa_enabled else 0,
                    mfa_secret,
                    1 if is_builtin else 0,
                    1 if must_change_password else 0,
                    now,
                ),
            )
        return self.get_user_by_username(username)  # type: ignore[return-value]

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username.strip().lower(),)
            ).fetchone()
            return dict(row) if row else None

    def list_users(self) -> List[Dict[str, Any]]:
        with self._lock, self._get_conn() as conn:
            rows = conn.execute(
                """
                SELECT user_id, username, full_name, role, mfa_enabled,
                       mfa_secret, is_builtin, must_change_password,
                       created_at_utc, last_login_utc
                FROM users
                ORDER BY created_at_utc ASC
                """
            ).fetchall()
            return [dict(r) for r in rows]

    def update_user_last_login(self, username: str) -> None:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._lock, self._get_conn() as conn:
            conn.execute(
                "UPDATE users SET last_login_utc = ? WHERE username = ?",
                (now, username.strip().lower()),
            )

    def update_user_password(
        self,
        username: str,
        new_password_hash: str,
        new_mfa_secret: Optional[str] = None,
    ) -> bool:
        with self._lock, self._get_conn() as conn:
            if new_mfa_secret:
                cur = conn.execute(
                    """
                    UPDATE users
                    SET password_hash = ?, mfa_secret = ?, must_change_password = 0
                    WHERE username = ?
                    """,
                    (new_password_hash, new_mfa_secret, username.strip().lower()),
                )
            else:
                cur = conn.execute(
                    """
                    UPDATE users
                    SET password_hash = ?, must_change_password = 0
                    WHERE username = ?
                    """,
                    (new_password_hash, username.strip().lower()),
                )
            return cur.rowcount > 0

    def set_user_bootstrap_flags(
        self, username: str, is_builtin: bool, must_change_password: bool
    ) -> None:
        with self._lock, self._get_conn() as conn:
            conn.execute(
                "UPDATE users SET is_builtin = ?, must_change_password = ? WHERE username = ?",
                (1 if is_builtin else 0, 1 if must_change_password else 0, username.strip().lower()),
            )

    def toggle_user_mfa(self, user_id: str, enabled: bool) -> bool:
        with self._lock, self._get_conn() as conn:
            cur = conn.execute(
                "UPDATE users SET mfa_enabled = ? WHERE user_id = ?",
                (1 if enabled else 0, user_id),
            )
            return cur.rowcount > 0

    def delete_user(self, user_id: str) -> bool:
        with self._lock, self._get_conn() as conn:
            cur = conn.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
            return cur.rowcount > 0

    # -----------------------------------------------------------------
    # HISTORIA ZMIAN, DRYFT KONFIGURACJI (DIFF VIEWER)
    # -----------------------------------------------------------------

    def get_report_by_id(self, report_id: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._get_conn() as conn:
            row = conn.execute("SELECT * FROM audit_reports WHERE report_id = ?", (report_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            d["anomaly_findings"] = json.loads(d.pop("anomaly_findings_json", "[]"))
            d["evaluated_results"] = json.loads(d.pop("evaluated_results_json", "[]"))
            d["raw_payload"] = json.loads(d.pop("raw_payload_json", "{}"))
            return d

    def compare_two_reports(self, old_report_id: str, new_report_id: str) -> Optional[Dict[str, Any]]:
        old_rep = self.get_report_by_id(old_report_id)
        new_rep = self.get_report_by_id(new_report_id)
        if not old_rep or not new_rep:
            return None

        old_map = {r["rule_id"]: r for r in old_rep.get("evaluated_results", [])}
        new_map = {r["rule_id"]: r for r in new_rep.get("evaluated_results", [])}
        all_rule_ids = list(dict.fromkeys(list(new_map.keys()) + list(old_map.keys())))

        changes: List[Dict[str, Any]] = []
        regressions = 0
        remediations = 0
        value_drifts = 0

        for rid in all_rule_ids:
            o = old_map.get(rid)
            n = new_map.get(rid)
            if not o and n:
                changes.append({
                    "rule_id": rid,
                    "title": n.get("title", rid),
                    "category": n.get("category", ""),
                    "risk_severity": n.get("risk_severity", "MEDIUM"),
                    "change_type": "NEW_RULE",
                    "old_status": "N/A",
                    "new_status": n.get("compliance_status"),
                    "old_value": None,
                    "new_value": n.get("observed_value"),
                    "remediation": n.get("remediation", ""),
                })
                continue
            if o and not n:
                continue

            assert o is not None and n is not None
            old_st = o.get("compliance_status")
            new_st = n.get("compliance_status")
            old_val = o.get("observed_value")
            new_val = n.get("observed_value")

            if old_st == new_st and old_val == new_val:
                change_type = "UNCHANGED"
            elif old_st == "PASS" and new_st in ("FAIL", "ERROR"):
                change_type = "REGRESSION"
                regressions += 1
            elif old_st in ("FAIL", "ERROR") and new_st == "PASS":
                change_type = "REMEDIATED"
                remediations += 1
            else:
                change_type = "VALUE_DRIFT"
                value_drifts += 1

            changes.append({
                "rule_id": rid,
                "title": n.get("title", rid),
                "category": n.get("category", ""),
                "risk_severity": n.get("risk_severity", "MEDIUM"),
                "change_type": change_type,
                "old_status": old_st,
                "new_status": new_st,
                "old_value": old_val,
                "new_value": new_val,
                "remediation": n.get("remediation", ""),
            })

        # Sortuj tak, aby regresje i naprawy były na górze
        priority = {"REGRESSION": 0, "REMEDIATED": 1, "VALUE_DRIFT": 2, "NEW_RULE": 3, "UNCHANGED": 4}
        changes.sort(key=lambda x: priority.get(x["change_type"], 9))

        return {
            "agent_id": new_rep["agent_id"],
            "hostname": new_rep["hostname"],
            "old_report": {
                "report_id": old_rep["report_id"],
                "ingested_at_utc": old_rep["ingested_at_utc"],
                "posture_score": old_rep["posture_score"],
                "pass_count": old_rep["pass_count"],
                "fail_count": old_rep["fail_count"],
            },
            "new_report": {
                "report_id": new_rep["report_id"],
                "ingested_at_utc": new_rep["ingested_at_utc"],
                "posture_score": new_rep["posture_score"],
                "pass_count": new_rep["pass_count"],
                "fail_count": new_rep["fail_count"],
            },
            "score_delta": round(new_rep["posture_score"] - old_rep["posture_score"], 1),
            "regressions_count": regressions,
            "remediations_count": remediations,
            "value_drifts_count": value_drifts,
            "items": changes,
        }

    # -----------------------------------------------------------------
    # KANAŁY ALERTÓW SOC (WEBHOOKS / SIEM / SLACK / TEAMS)
    # -----------------------------------------------------------------

    def create_webhook_channel(
        self,
        channel_id: str,
        name: str,
        provider: str,
        target_url: str,
        min_severity: str = "HIGH",
        score_threshold: float = 70.0,
        trigger_on_drift: bool = True,
        trigger_on_poisoning: bool = True,
    ) -> Dict[str, Any]:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._lock, self._get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO alert_webhooks (
                    channel_id, name, provider, target_url, min_severity,
                    score_threshold, trigger_on_drift, trigger_on_poisoning,
                    enabled, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (
                    channel_id,
                    name,
                    provider.upper(),
                    target_url,
                    min_severity.upper(),
                    score_threshold,
                    1 if trigger_on_drift else 0,
                    1 if trigger_on_poisoning else 0,
                    now,
                ),
            )
            row = conn.execute("SELECT * FROM alert_webhooks WHERE channel_id = ?", (channel_id,)).fetchone()
            return dict(row) if row else {}

    def list_webhook_channels(self) -> List[Dict[str, Any]]:
        with self._lock, self._get_conn() as conn:
            rows = conn.execute("SELECT * FROM alert_webhooks ORDER BY created_at_utc ASC").fetchall()
            return [dict(r) for r in rows]

    def delete_webhook_channel(self, channel_id: str) -> bool:
        with self._lock, self._get_conn() as conn:
            cur = conn.execute("DELETE FROM alert_webhooks WHERE channel_id = ?", (channel_id,))
            return cur.rowcount > 0

    def record_webhook_delivery(
        self,
        channel_id: str,
        channel_name: str,
        provider: str,
        event_trigger: str,
        severity: str,
        agent_id: Optional[str],
        delivery_status: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._lock, self._get_conn() as conn:
            cur = conn.execute(
                """
                INSERT INTO alert_deliveries (
                    timestamp_utc, channel_id, channel_name, provider,
                    event_trigger, severity, agent_id, delivery_status, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    channel_id,
                    channel_name,
                    provider,
                    event_trigger,
                    severity,
                    agent_id,
                    delivery_status,
                    json.dumps(payload, ensure_ascii=False),
                ),
            )
            row = conn.execute("SELECT * FROM alert_deliveries WHERE delivery_id = ?", (cur.lastrowid,)).fetchone()
            d = dict(row)
            d["payload"] = json.loads(d.pop("payload_json", "{}"))
            return d

    def list_webhook_deliveries(self, limit: int = 30) -> List[Dict[str, Any]]:
        with self._lock, self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM alert_deliveries ORDER BY delivery_id DESC LIMIT ?", (limit,)
            ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["payload"] = json.loads(d.pop("payload_json", "{}"))
                out.append(d)
            return out

