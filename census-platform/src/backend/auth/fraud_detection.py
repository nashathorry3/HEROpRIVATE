"""
Census Platform — Fraud Detection Engine
Multi-layer fraud detection: rules → ML → graph analysis
"""
import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import numpy as np
import joblib

from ..core.config import get_settings
from ..core.audit import emit_audit_event

settings = get_settings()


class FraudDecision(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"          # Human review queue
    BLOCK = "block"
    CHALLENGE = "challenge"    # Additional verification step


@dataclass
class RegistrationContext:
    """Context signals collected at registration time."""
    phone_hash: bytes
    device_fingerprint_hash: bytes
    ip_hash: bytes
    timezone: str
    locale: str
    channel: str                          # 'web'|'mobile'|'agent'|'ussd'
    user_agent_hash: bytes
    timestamp: float = field(default_factory=time.time)
    geolocation_region: Optional[str] = None
    typing_rhythm_score: Optional[float] = None
    mouse_dynamics_score: Optional[float] = None
    session_duration_seconds: Optional[int] = None


@dataclass
class FraudSignals:
    """Computed fraud signals from rules engine."""
    ip_velocity_score: float = 0.0          # Registrations from same IP/hour
    device_reuse_count: int = 0             # Times this device used
    phone_reputation_score: float = 0.0    # External phone reputation API
    behavioral_anomaly_score: float = 0.0  # Typing/mouse patterns
    geo_consistency_score: float = 1.0     # 1=consistent, 0=anomalous
    time_pattern_score: float = 1.0        # Bot-like timing patterns
    ml_fraud_score: float = 0.0            # ML model output


@dataclass
class FraudResult:
    decision: FraudDecision
    overall_score: float
    signals: FraudSignals
    block_reason: Optional[str] = None
    review_reason: Optional[str] = None


class RulesEngine:
    """
    Fast rule-based fraud checks (< 10ms target).
    Applied before expensive ML inference.
    """

    async def evaluate(
        self, ctx: RegistrationContext, redis_client
    ) -> tuple[FraudSignals, Optional[FraudDecision]]:
        signals = FraudSignals()
        immediate_block = None

        # Rule 1: IP velocity
        ip_key = f"fraud:ip:{ctx.ip_hash.hex()}"
        ip_count = await redis_client.incr(ip_key)
        if ip_count == 1:
            await redis_client.expire(ip_key, 3600)
        signals.ip_velocity_score = min(ip_count / 10.0, 1.0)
        if ip_count > 10:
            immediate_block = FraudDecision.BLOCK

        # Rule 2: Device reuse
        device_key = f"fraud:device:{ctx.device_fingerprint_hash.hex()}"
        device_count = await redis_client.incr(device_key)
        if device_count == 1:
            await redis_client.expire(device_key, 86400)
        signals.device_reuse_count = device_count
        if device_count > 1:
            immediate_block = FraudDecision.BLOCK  # One device = one registration

        # Rule 3: Time pattern (bot detection)
        # Bots register at exact intervals; humans have variance
        time_key = f"fraud:timing:{ctx.ip_hash.hex()}"
        previous_time = await redis_client.get(time_key)
        if previous_time:
            interval = ctx.timestamp - float(previous_time)
            if interval < 2.0:  # Less than 2 seconds between registrations
                signals.time_pattern_score = 0.1
                immediate_block = FraudDecision.BLOCK
        await redis_client.setex(time_key, 3600, str(ctx.timestamp))

        # Rule 4: Behavioral signals
        if ctx.typing_rhythm_score is not None:
            signals.behavioral_anomaly_score = 1.0 - ctx.typing_rhythm_score
            if ctx.typing_rhythm_score < 0.3:  # Very bot-like typing
                immediate_block = FraudDecision.CHALLENGE

        return signals, immediate_block


class MLFraudModel:
    """
    XGBoost ensemble fraud detection model.
    Trained on historical fraud patterns with differential privacy.
    """

    def __init__(self, model_path: str):
        try:
            self._model = joblib.load(model_path)
        except Exception:
            self._model = None  # Graceful degradation

    def predict(self, signals: FraudSignals, ctx: RegistrationContext) -> float:
        """Returns fraud probability in [0, 1]."""
        if self._model is None:
            return 0.0  # Fail open — ML unavailable

        features = np.array([[
            signals.ip_velocity_score,
            float(signals.device_reuse_count > 0),
            signals.phone_reputation_score,
            signals.behavioral_anomaly_score,
            signals.geo_consistency_score,
            signals.time_pattern_score,
            float(ctx.channel == "web"),
            float(ctx.channel == "mobile"),
            float(ctx.session_duration_seconds or 300) / 600.0,
        ]])

        try:
            prob = self._model.predict_proba(features)[0][1]
            return float(prob)
        except Exception:
            return 0.0


class FraudDetectionService:
    """
    Orchestrates multi-layer fraud detection.
    Decision hierarchy: Rules (fast) → ML (accurate) → Human review
    """

    def __init__(self, redis_client, ml_model: Optional[MLFraudModel] = None):
        self._redis = redis_client
        self._rules = RulesEngine()
        self._ml_model = ml_model or MLFraudModel(settings.FRAUD_MODEL_PATH)

    async def evaluate(self, ctx: RegistrationContext) -> FraudResult:
        # Layer 1: Rules (immediate decisions)
        signals, immediate_decision = await self._rules.evaluate(ctx, self._redis)

        if immediate_decision == FraudDecision.BLOCK:
            await emit_audit_event(
                event_type="fraud.blocked_by_rules",
                actor_hash=ctx.device_fingerprint_hash,
                outcome="blocked",
                metadata={
                    "ip_velocity": signals.ip_velocity_score,
                    "device_reuse": signals.device_reuse_count,
                },
            )
            return FraudResult(
                decision=FraudDecision.BLOCK,
                overall_score=1.0,
                signals=signals,
                block_reason="rules_engine_block",
            )

        # Layer 2: ML model
        ml_score = self._ml_model.predict(signals, ctx)
        signals.ml_fraud_score = ml_score

        overall_score = self._compute_weighted_score(signals)

        # Decision threshold
        if overall_score >= settings.FRAUD_SCORE_BLOCK_THRESHOLD:
            decision = FraudDecision.BLOCK
            block_reason = "ml_high_confidence_fraud"
            review_reason = None
        elif overall_score >= settings.FRAUD_SCORE_REVIEW_THRESHOLD:
            decision = FraudDecision.REVIEW
            block_reason = None
            review_reason = f"fraud_score_{overall_score:.2f}"
        elif immediate_decision == FraudDecision.CHALLENGE:
            decision = FraudDecision.CHALLENGE
            block_reason = None
            review_reason = "behavioral_anomaly"
        else:
            decision = FraudDecision.ALLOW
            block_reason = None
            review_reason = None

        await emit_audit_event(
            event_type=f"fraud.{decision.value}",
            actor_hash=ctx.device_fingerprint_hash,
            outcome="success" if decision == FraudDecision.ALLOW else "flagged",
            risk_score=overall_score,
            metadata={"decision": decision.value, "score": overall_score},
        )

        return FraudResult(
            decision=decision,
            overall_score=overall_score,
            signals=signals,
            block_reason=block_reason,
            review_reason=review_reason,
        )

    @staticmethod
    def _compute_weighted_score(signals: FraudSignals) -> float:
        """
        Weighted combination of fraud signals.
        Weights tuned on historical data; reviewed quarterly.
        """
        weights = {
            "ip_velocity": 0.15,
            "device_reuse": 0.25,
            "phone_reputation": 0.10,
            "behavioral": 0.15,
            "geo_consistency": 0.10,
            "time_pattern": 0.10,
            "ml_model": 0.15,
        }

        device_score = 1.0 if signals.device_reuse_count > 0 else 0.0

        weighted = (
            signals.ip_velocity_score * weights["ip_velocity"]
            + device_score * weights["device_reuse"]
            + signals.phone_reputation_score * weights["phone_reputation"]
            + signals.behavioral_anomaly_score * weights["behavioral"]
            + (1.0 - signals.geo_consistency_score) * weights["geo_consistency"]
            + (1.0 - signals.time_pattern_score) * weights["time_pattern"]
            + signals.ml_fraud_score * weights["ml_model"]
        )

        return min(max(weighted, 0.0), 1.0)
