"""
Census Platform — Database Models & Migration Script
SQLAlchemy models for both Identity DB and Census DB
"""
from datetime import datetime, timezone
from typing import Optional
import uuid

from sqlalchemy import (
    Column, String, Boolean, Integer, SmallInteger, Numeric,
    DateTime, LargeBinary, Text, ForeignKey, CheckConstraint,
    event, DDL, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.ext.asyncio import AsyncAttrs


class IdentityBase(AsyncAttrs, DeclarativeBase):
    """Base for Identity Database models."""
    pass


class CensusBase(AsyncAttrs, DeclarativeBase):
    """Base for Census (demographic) Database models."""
    pass


# ═══════════════════════════════════════════════════════════════
# IDENTITY DATABASE MODELS
# High-security zone — no demographic data here
# ═══════════════════════════════════════════════════════════════

class Device(IdentityBase):
    __tablename__ = "devices"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    fingerprint_hash = Column(LargeBinary(32), nullable=False, index=True)
    risk_score = Column(Numeric(3, 2), default=0.0)
    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    registration_count = Column(SmallInteger, default=0)
    is_blocked = Column(Boolean, default=False)
    block_reason = Column(String(100))

    citizens = relationship("Citizen", back_populates="device")


class Citizen(IdentityBase):
    __tablename__ = "citizens"
    __table_args__ = (
        CheckConstraint("verification_level BETWEEN 1 AND 3", name="valid_verification_level"),
        CheckConstraint(
            "enrollment_path IN ('document', 'phone', 'biometric', 'agent')",
            name="valid_enrollment_path",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    phone_hash = Column(LargeBinary(32), unique=True, nullable=False, index=True)
    face_hash = Column(LargeBinary(32), unique=True, nullable=True)
    document_hash = Column(LargeBinary(32), unique=True, nullable=True)
    enrollment_path = Column(String(20), nullable=False)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"))
    zkp_token_id = Column(UUID(as_uuid=True), unique=True, nullable=False)
    enrollment_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    verification_level = Column(SmallInteger, nullable=False, default=1)
    is_active = Column(Boolean, default=True)

    device = relationship("Device", back_populates="citizens")


class OTPSession(IdentityBase):
    __tablename__ = "otp_sessions"
    __table_args__ = (
        CheckConstraint("attempts <= 3", name="max_attempts"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    phone_hash = Column(LargeBinary(32), nullable=False, index=True)
    otp_hash = Column(LargeBinary(60), nullable=False)      # bcrypt output
    expires_at = Column(DateTime(timezone=True), nullable=False)
    attempts = Column(SmallInteger, default=0)
    verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class FieldAgent(IdentityBase):
    __tablename__ = "field_agents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_code = Column(String(20), unique=True, nullable=False)
    region_code = Column(String(10), nullable=False)
    public_key = Column(Text, nullable=False)       # Ed25519 public key
    is_active = Column(Boolean, default=True)
    attestations_count = Column(Integer, default=0)
    max_daily_attestations = Column(Integer, default=50)


class ZKPToken(IdentityBase):
    __tablename__ = "zkp_tokens"

    token_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    proof_data = Column(LargeBinary, nullable=False)
    circuit_version = Column(String(10), nullable=False)
    nullifier_hash = Column(LargeBinary(32), unique=True, nullable=False)
    issued_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    census_used = Column(Boolean, default=False)
    census_used_at = Column(DateTime(timezone=True))


# ═══════════════════════════════════════════════════════════════
# CENSUS (DEMOGRAPHIC) DATABASE MODELS
# Anonymized — NO identity information
# ═══════════════════════════════════════════════════════════════

class Region(CensusBase):
    __tablename__ = "regions"

    code = Column(String(10), primary_key=True)
    name_local = Column(String(100), nullable=False)
    name_en = Column(String(100), nullable=False)
    parent_code = Column(String(10), ForeignKey("regions.code"))
    level = Column(SmallInteger, nullable=False)
    population_min = Column(Integer)
    is_active = Column(Boolean, default=True)


class Ethnicity(CensusBase):
    __tablename__ = "ethnicities"

    code = Column(String(20), primary_key=True)
    name_local = Column(String(100), nullable=False)
    name_en = Column(String(100), nullable=False)
    is_active = Column(Boolean, default=True)


class Language(CensusBase):
    __tablename__ = "languages"

    code = Column(String(20), primary_key=True)
    name_local = Column(String(100), nullable=False)
    name_en = Column(String(100), nullable=False)
    script = Column(String(20))


class Religion(CensusBase):
    __tablename__ = "religions"

    code = Column(String(20), primary_key=True)
    name_local = Column(String(100), nullable=False)
    name_en = Column(String(100), nullable=False)
    category = Column(String(50))


class CensusResponse(CensusBase):
    __tablename__ = "census_responses"
    __table_args__ = (
        CheckConstraint(
            "age_bracket IN ('under-18','18-24','25-34','35-44','45-54','55-64','65+')",
            name="valid_age_bracket",
        ),
        CheckConstraint("household_size BETWEEN 1 AND 30", name="valid_household_size"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token_nullifier = Column(LargeBinary(32), unique=True, nullable=False)

    # Geographic (district level max — no street addresses)
    region_code = Column(String(10), ForeignKey("regions.code"), nullable=False)
    district_code = Column(String(10))
    is_urban = Column(Boolean)

    # Demographic (self-reported)
    ethnicity_code = Column(String(20), ForeignKey("ethnicities.code"))
    language_code = Column(String(20), ForeignKey("languages.code"))
    religion_code = Column(String(20), ForeignKey("religions.code"))
    age_bracket = Column(String(10))
    gender_code = Column(String(10))
    household_size = Column(SmallInteger)

    # Socioeconomic
    education_level = Column(String(20))
    employment_status = Column(String(20))
    housing_type = Column(String(20))

    # Submission metadata (no PII)
    submission_channel = Column(String(20))
    submission_region = Column(String(10))
    submitted_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    completion_rate = Column(Numeric(3, 2))
    response_time_seconds = Column(Integer)


# ═══════════════════════════════════════════════════════════════
# AUDIT DATABASE MODELS
# Append-only — modifications prevented at DB level
# ═══════════════════════════════════════════════════════════════

class AuditLog(IdentityBase):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String(50), nullable=False)
    event_time = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    actor_type = Column(String(20))
    actor_hash = Column(LargeBinary(32))
    action = Column(String(100))
    resource_type = Column(String(50))
    outcome = Column(String(10), nullable=False)
    risk_score = Column(Numeric(3, 2))
    metadata = Column(JSONB)
    signature = Column(LargeBinary(32), nullable=False)  # HMAC-SHA256


# Prevent UPDATE/DELETE on audit_log at application level
# The DB-level prevention is in the migration SQL (see ARCHITECTURE.md)
@event.listens_for(AuditLog, "before_update")
def prevent_audit_update(mapper, connection, target):
    raise RuntimeError("Audit log is immutable — updates are prohibited.")

@event.listens_for(AuditLog, "before_delete")
def prevent_audit_delete(mapper, connection, target):
    raise RuntimeError("Audit log is immutable — deletion is prohibited.")
