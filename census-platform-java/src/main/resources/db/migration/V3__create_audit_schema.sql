-- ============================================================
-- V3: Audit Trail Schema — Append-Only, Tamper-Evident
-- ============================================================

CREATE SCHEMA IF NOT EXISTS audit;

CREATE TABLE audit.audit_log (
    id          BIGSERIAL PRIMARY KEY,
    event_type  VARCHAR(50) NOT NULL,
    event_time  TIMESTAMPTZ DEFAULT NOW(),
    actor_type  VARCHAR(20),
    actor_hash  BYTEA,          -- Hashed identifier — no raw PII
    outcome     VARCHAR(10) NOT NULL,
    risk_score  NUMERIC(3,2),
    signature   BYTEA NOT NULL,  -- HMAC-SHA256 of row content
    CONSTRAINT valid_outcome CHECK (
        outcome IN ('success','failure','blocked','flagged','evaluated')
    )
);

CREATE TABLE audit.audit_log_metadata (
    audit_log_id BIGINT NOT NULL REFERENCES audit.audit_log(id),
    key          VARCHAR(100) NOT NULL,
    value        TEXT,
    PRIMARY KEY (audit_log_id, key)
);

CREATE INDEX idx_audit_event_type  ON audit.audit_log (event_type);
CREATE INDEX idx_audit_event_time  ON audit.audit_log (event_time DESC);
CREATE INDEX idx_audit_outcome     ON audit.audit_log (outcome);

-- ─── Immutability Enforcement ─────────────────────────────────
-- Prevent UPDATE and DELETE at the database level

CREATE OR REPLACE FUNCTION audit.prevent_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit log is immutable. Modification not allowed.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER no_update_audit_log
    BEFORE UPDATE ON audit.audit_log
    FOR EACH ROW EXECUTE FUNCTION audit.prevent_modification();

CREATE TRIGGER no_delete_audit_log
    BEFORE DELETE ON audit.audit_log
    FOR EACH ROW EXECUTE FUNCTION audit.prevent_modification();

CREATE TRIGGER no_update_audit_metadata
    BEFORE UPDATE ON audit.audit_log_metadata
    FOR EACH ROW EXECUTE FUNCTION audit.prevent_modification();

CREATE TRIGGER no_delete_audit_metadata
    BEFORE DELETE ON audit.audit_log_metadata
    FOR EACH ROW EXECUTE FUNCTION audit.prevent_modification();

-- ─── Row-Level Security ───────────────────────────────────────
-- Analysts can only read, never write
ALTER TABLE audit.audit_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY audit_read_policy ON audit.audit_log
    FOR SELECT
    USING (true);  -- Read allowed for all authenticated roles

-- No INSERT/UPDATE/DELETE policies = those are blocked by default
