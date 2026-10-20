-- =============================================================================
-- SystemAuditor Enterprise — Produkcyjny Schemat PostgreSQL 16 + TimescaleDB
-- =============================================================================
-- Przeznaczenie: Obsługa 10 000+ endpointów (Windows & Linux) z partycjonowaniem
-- szeregów czasowych (Hypertables), indeksami GIN na kolumnach JSONB, polityką
-- kompresji kolumnowej oraz izolacją niemodyfikowalnych logów (Append-Only).
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "timescaledb";

-- 1. Tabela Zarejestrowanych Agentów (Stan bieżący + Tożsamość X.509 SPIFFE)
CREATE TABLE agents (
    agent_id            UUID PRIMARY KEY,
    hostname            VARCHAR(255) NOT NULL,
    os_family           VARCHAR(32) NOT NULL CHECK (os_family IN ('Windows', 'Linux')),
    os_release          VARCHAR(128) NOT NULL,
    architecture        VARCHAR(32) NOT NULL,
    ip_address          INET NOT NULL,
    is_elevated         BOOLEAN NOT NULL DEFAULT FALSE,
    policy_version      VARCHAR(64) NOT NULL,
    cert_serial_hex     VARCHAR(128) UNIQUE,
    spiffe_id           VARCHAR(255) UNIQUE NOT NULL,
    cert_expires_at     TIMESTAMPTZ NOT NULL,
    status              VARCHAR(24) NOT NULL DEFAULT 'ONLINE'
                        CHECK (status IN ('ONLINE', 'OFFLINE', 'QUARANTINED', 'REVOKED')),
    last_heartbeat_utc  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_audit_utc      TIMESTAMPTZ,
    current_score       NUMERIC(5,2) NOT NULL DEFAULT 0.00,
    pass_count          INTEGER NOT NULL DEFAULT 0,
    fail_count          INTEGER NOT NULL DEFAULT 0,
    boot_id             VARCHAR(128),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agents_status_score ON agents (status, current_score ASC);
CREATE INDEX idx_agents_os_family ON agents (os_family);

-- 2. Tabela Raportów Audytowych (TimescaleDB Hypertable - Append-Only Ledger)
CREATE TABLE audit_reports (
    ingested_at_utc     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    report_id           UUID NOT NULL,
    agent_id            UUID NOT NULL REFERENCES agents(agent_id),
    hostname            VARCHAR(255) NOT NULL,
    os_family           VARCHAR(32) NOT NULL,
    policy_version      VARCHAR(64) NOT NULL,
    submitted_at_utc    TIMESTAMPTZ NOT NULL,
    posture_score       NUMERIC(5,2) NOT NULL,
    pass_count          INTEGER NOT NULL,
    fail_count          INTEGER NOT NULL,
    error_count         INTEGER NOT NULL,
    na_count            INTEGER NOT NULL,
    is_quarantined      BOOLEAN NOT NULL DEFAULT FALSE,
    anomaly_risk_score  SMALLINT NOT NULL DEFAULT 0,
    anomaly_findings    JSONB NOT NULL DEFAULT '[]'::jsonb,
    evaluated_results   JSONB NOT NULL,
    raw_payload         JSONB NOT NULL,
    PRIMARY KEY (ingested_at_utc, report_id)
);

-- Konwersja do TimescaleDB Hypertable z chunkami 7-dniowymi
SELECT create_hypertable('audit_reports', 'ingested_at_utc', chunk_time_interval => INTERVAL '7 days');

-- Indeksy GIN dla błyskawicznego wyszukiwania po zagnieżdżonych polach JSONB (np. konkretna reguła CIS lub technika MITRE)
CREATE INDEX idx_audit_reports_agent_time ON audit_reports (agent_id, ingested_at_utc DESC);
CREATE INDEX idx_audit_reports_evaluated_gin ON audit_reports USING GIN (evaluated_results jsonb_path_ops);
CREATE INDEX idx_audit_reports_quarantine ON audit_reports (is_quarantined, ingested_at_utc DESC) WHERE is_quarantined = TRUE;

-- Polityka automatycznej kompresji kolumnowej dla danych starszych niż 14 dni (redukcja storage o ~88%)
ALTER TABLE audit_reports SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'agent_id, os_family',
    timescaledb.compress_orderby = 'ingested_at_utc DESC'
);
SELECT add_compression_policy('audit_reports', INTERVAL '14 days');

-- Polityka retencji (automatyczne usuwanie chunków starszych niż 365 dni)
SELECT add_retention_policy('audit_reports', INTERVAL '365 days');

-- 3. Ochrona przed modyfikacją historycznych logów (Append-Only Trigger przeciwko Poisoning)
CREATE OR REPLACE FUNCTION prevent_audit_log_tampering()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Operacje UPDATE oraz DELETE na tabeli audit_reports są zablokowane (Immutable Audit Ledger).';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_immutable_audit_reports
BEFORE UPDATE OR DELETE ON audit_reports
FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_tampering();
