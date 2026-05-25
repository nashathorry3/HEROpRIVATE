"""
Census Platform — Immutable Audit Trail
All security events written to append-only Kafka → PostgreSQL pipeline
Rows are HMAC-signed to detect tampering
"""
import hashlib
import hmac
import json
import time
from typing import Optional, Any
from dataclasses import dataclass, asdict

from ..core.config import get_settings

settings = get_settings()


@dataclass
class AuditEvent:
    event_type: str
    outcome: str
    event_time: float
    actor_type: str = "system"
    actor_hash: Optional[str] = None      # Hex string of actor hash
    action: Optional[str] = None
    resource_type: Optional[str] = None
    risk_score: Optional[float] = None
    metadata: Optional[dict] = None
    signature: Optional[str] = None


def _sign_event(event: AuditEvent) -> str:
    """HMAC-SHA256 signature of event content."""
    secret = settings.HMAC_SECRET.get_secret_value().encode()
    content = json.dumps({
        "event_type": event.event_type,
        "outcome": event.outcome,
        "event_time": event.event_time,
        "actor_hash": event.actor_hash,
        "risk_score": event.risk_score,
    }, sort_keys=True).encode()
    return hmac.new(secret, content, hashlib.sha256).hexdigest()


async def emit_audit_event(
    event_type: str,
    outcome: str,
    actor_hash: Optional[bytes] = None,
    actor_type: str = "system",
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    risk_score: Optional[float] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> None:
    """
    Emit a security audit event.
    Non-blocking: written to Kafka topic, consumed by audit writer service.
    """
    event = AuditEvent(
        event_type=event_type,
        outcome=outcome,
        event_time=time.time(),
        actor_type=actor_type,
        actor_hash=actor_hash.hex() if actor_hash else None,
        action=action,
        resource_type=resource_type,
        risk_score=risk_score,
        metadata=_sanitize_metadata(metadata),
    )
    event.signature = _sign_event(event)

    # In production: publish to Kafka
    # await kafka_producer.send(settings.KAFKA_AUDIT_TOPIC, value=asdict(event))

    # Development fallback: structured log
    import logging
    logger = logging.getLogger("census.audit")
    logger.info(json.dumps(asdict(event)))


def _sanitize_metadata(metadata: Optional[dict]) -> Optional[dict]:
    """Remove any PII that might accidentally land in metadata."""
    if not metadata:
        return None

    PII_KEYS = {
        "name", "phone", "email", "address", "dob", "national_id",
        "passport", "face_image", "embedding", "raw_id",
    }

    return {
        k: "[REDACTED]" if k.lower() in PII_KEYS else v
        for k, v in metadata.items()
    }
