-- ============================================================
-- V1: Identity Database Schema
-- High-security zone — NO demographic data
-- ============================================================

CREATE SCHEMA IF NOT EXISTS identity;

-- ─── Extensions ──────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─── Devices ─────────────────────────────────────────────────
CREATE TABLE identity.devices (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fingerprint_hash    BYTEA NOT NULL,
    risk_score          NUMERIC(3,2) DEFAULT 0.0,
    first_seen          TIMESTAMPTZ DEFAULT NOW(),
    last_seen           TIMESTAMPTZ DEFAULT NOW(),
    registration_count  SMALLINT DEFAULT 0,
    is_blocked          BOOLEAN DEFAULT FALSE,
    block_reason        VARCHAR(100),
    CONSTRAINT valid_risk_score CHECK (risk_score BETWEEN 0.0 AND 1.0)
);

CREATE INDEX idx_devices_fingerprint ON identity.devices (fingerprint_hash);

-- ─── Citizens ────────────────────────────────────────────────
CREATE TABLE identity.citizens (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    phone_hash          BYTEA NOT NULL UNIQUE,
    face_hash           BYTEA UNIQUE,
    document_hash       BYTEA UNIQUE,
    enrollment_path     VARCHAR(20) NOT NULL,
    device_id           UUID REFERENCES identity.devices(id),
    zkp_token_id        UUID NOT NULL UNIQUE,
    verification_level  SMALLINT NOT NULL DEFAULT 1,
    is_active           BOOLEAN DEFAULT TRUE,
    enrollment_at       TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT valid_verification_level  CHECK (verification_level BETWEEN 1 AND 3),
    CONSTRAINT valid_enrollment_path     CHECK (
        enrollment_path IN ('DOCUMENT','PHONE','BIOMETRIC','AGENT')
    )
);

CREATE INDEX idx_citizens_phone_hash     ON identity.citizens (phone_hash);
CREATE INDEX idx_citizens_verification   ON identity.citizens (verification_level);

-- ─── OTP Sessions ────────────────────────────────────────────
CREATE TABLE identity.otp_sessions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    phone_hash  BYTEA NOT NULL,
    otp_hash    VARCHAR(60) NOT NULL,  -- bcrypt output
    expires_at  TIMESTAMPTZ NOT NULL,
    attempts    SMALLINT DEFAULT 0,
    verified    BOOLEAN DEFAULT FALSE,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT max_attempts CHECK (attempts <= 3)
);

CREATE INDEX idx_otp_phone_hash ON identity.otp_sessions (phone_hash);

-- Auto-cleanup expired OTP sessions (pg_cron job in production)
-- SELECT cron.schedule('*/5 * * * *', $$
--     DELETE FROM identity.otp_sessions WHERE expires_at < NOW();
-- $$);

-- ─── ZKP Tokens ──────────────────────────────────────────────
CREATE TABLE identity.zkp_tokens (
    token_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nullifier_hash      BYTEA NOT NULL UNIQUE,
    proof_data          BYTEA NOT NULL,
    circuit_version     VARCHAR(10) NOT NULL,
    verification_level  SMALLINT NOT NULL DEFAULT 1,
    issued_at           TIMESTAMPTZ DEFAULT NOW(),
    census_used         BOOLEAN DEFAULT FALSE,
    census_used_at      TIMESTAMPTZ,
    CONSTRAINT valid_circuit_version CHECK (circuit_version ~ '^v\d+\.\d+\.\d+$')
);

CREATE INDEX idx_zkp_nullifier ON identity.zkp_tokens (nullifier_hash);

-- ─── Field Agents ─────────────────────────────────────────────
CREATE TABLE identity.field_agents (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_code              VARCHAR(20) NOT NULL UNIQUE,
    region_code             VARCHAR(10) NOT NULL,
    public_key              TEXT NOT NULL,  -- Ed25519 public key (hex)
    is_active               BOOLEAN DEFAULT TRUE,
    attestations_count      INTEGER DEFAULT 0,
    max_daily_attestations  INTEGER DEFAULT 50,
    created_at              TIMESTAMPTZ DEFAULT NOW()
);
