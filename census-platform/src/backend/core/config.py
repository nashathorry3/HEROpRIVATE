"""
Census Platform — Core Configuration
Environment-based configuration with secrets from HashiCorp Vault / AWS Secrets Manager
"""
from pydantic_settings import BaseSettings
from pydantic import Field, SecretStr
from functools import lru_cache
from typing import Literal


class Settings(BaseSettings):
    # ─── App ───────────────────────────────────────────────────────────
    APP_NAME: str = "National Census Platform"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: Literal["development", "staging", "production"] = "production"
    DEBUG: bool = False

    # ─── Database ──────────────────────────────────────────────────────
    # Identity DB — high-security zone
    IDENTITY_DB_URL: SecretStr = Field(..., env="IDENTITY_DB_URL")
    # Demographic DB — analytics zone (anonymized)
    CENSUS_DB_URL: SecretStr = Field(..., env="CENSUS_DB_URL")
    # Audit DB — append-only, write-only credentials
    AUDIT_DB_URL: SecretStr = Field(..., env="AUDIT_DB_URL")

    # ─── Redis ─────────────────────────────────────────────────────────
    REDIS_URL: SecretStr = Field(..., env="REDIS_URL")
    OTP_TTL_SECONDS: int = 300         # 5 minutes
    OTP_MAX_ATTEMPTS: int = 3
    RATE_LIMIT_WINDOW_SECONDS: int = 600
    RATE_LIMIT_MAX_REQUESTS: int = 5

    # ─── Crypto ────────────────────────────────────────────────────────
    GLOBAL_PHONE_SALT: SecretStr = Field(..., env="GLOBAL_PHONE_SALT")
    ENCRYPTION_KEY: SecretStr = Field(..., env="ENCRYPTION_KEY")
    HMAC_SECRET: SecretStr = Field(..., env="HMAC_SECRET")
    ZKP_CIRCUIT_HASH: str = Field(..., env="ZKP_CIRCUIT_HASH")

    # ─── OTP Delivery ──────────────────────────────────────────────────
    TWILIO_ACCOUNT_SID: SecretStr = Field(..., env="TWILIO_ACCOUNT_SID")
    TWILIO_AUTH_TOKEN: SecretStr = Field(..., env="TWILIO_AUTH_TOKEN")
    TWILIO_FROM_NUMBER: str = Field(..., env="TWILIO_FROM_NUMBER")
    AFRICAS_TALKING_API_KEY: SecretStr = Field(..., env="AFRICAS_TALKING_API_KEY")
    WHATSAPP_API_TOKEN: SecretStr = Field(..., env="WHATSAPP_API_TOKEN")

    # ─── Face Verification ─────────────────────────────────────────────
    FACE_SIMILARITY_THRESHOLD: float = 0.85
    FACE_LIVENESS_THRESHOLD: float = 0.92
    FAISS_INDEX_PATH: str = "/data/faiss/face_index.bin"
    FACENET_MODEL_PATH: str = "/models/facenet_512.onnx"
    LIVENESS_MODEL_PATH: str = "/models/liveness_detector.onnx"

    # ─── OCR ───────────────────────────────────────────────────────────
    OCR_PADDLE_MODEL_PATH: str = "/models/paddleocr"
    DOCUMENT_IMAGE_RETENTION_MINUTES: int = 15

    # ─── Fraud Detection ───────────────────────────────────────────────
    FRAUD_SCORE_BLOCK_THRESHOLD: float = 0.85
    FRAUD_SCORE_REVIEW_THRESHOLD: float = 0.70
    FRAUD_MODEL_PATH: str = "/models/fraud_detector.joblib"

    # ─── Kafka ─────────────────────────────────────────────────────────
    KAFKA_BOOTSTRAP_SERVERS: str = Field(..., env="KAFKA_BOOTSTRAP_SERVERS")
    KAFKA_AUDIT_TOPIC: str = "census.audit.events"
    KAFKA_FRAUD_TOPIC: str = "census.fraud.alerts"
    KAFKA_SYNC_TOPIC: str = "census.offline.sync"

    # ─── Compliance ────────────────────────────────────────────────────
    K_ANONYMITY_THRESHOLD: int = 100    # Suppress stats if group < 100
    MAX_GEOGRAPHIC_PRECISION: int = 3   # District level (not street)
    DATA_RETENTION_IDENTITY_MONTHS: int = 12
    DATA_RETENTION_CENSUS_YEARS: int = 10

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()
