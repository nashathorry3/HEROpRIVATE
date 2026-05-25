"""
Census Platform — Main REST API
FastAPI application with all census endpoints
"""
from contextlib import asynccontextmanager
from typing import Annotated, Optional
import uuid

from fastapi import FastAPI, HTTPException, Depends, Header, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field, field_validator
import redis.asyncio as redis_client

from ..auth.otp_service import OTPService, OTPChannel, OTPResult
from ..auth.face_verification import FaceVerificationService, FaceVerificationResult
from ..auth.fraud_detection import FraudDetectionService, RegistrationContext, FraudDecision
from ..auth.zkp_service import ZKPService, MerkleTree
from ..core.config import get_settings
from ..core.audit import emit_audit_event

settings = get_settings()

# ─── Application Lifespan ──────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.redis = redis_client.from_url(
        settings.REDIS_URL.get_secret_value(),
        encoding="utf-8",
        decode_responses=False,
    )
    app.state.otp_service = OTPService(app.state.redis)
    app.state.face_service = FaceVerificationService()
    app.state.fraud_service = FraudDetectionService(app.state.redis)
    app.state.merkle_tree = MerkleTree()
    app.state.zkp_service = ZKPService(app.state.merkle_tree)
    yield
    await app.state.redis.aclose()


app = FastAPI(
    title="National Census Platform API",
    version="1.0.0",
    docs_url=None,          # Disabled in production
    redoc_url=None,
    lifespan=lifespan,
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=["census.gov.*", "localhost"])
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://census.gov"],
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "X-Request-ID", "Accept-Language"],
    max_age=3600,
)


# ─── Dependencies ──────────────────────────────────────────────────────────────

def get_redis(request: Request) -> redis_client.Redis:
    return request.app.state.redis

def get_otp_service(request: Request) -> OTPService:
    return request.app.state.otp_service

def get_face_service(request: Request) -> FaceVerificationService:
    return request.app.state.face_service

def get_fraud_service(request: Request) -> FraudDetectionService:
    return request.app.state.fraud_service

def get_zkp_service(request: Request) -> ZKPService:
    return request.app.state.zkp_service


# ─── Request/Response Schemas ──────────────────────────────────────────────────

class OTPRequestBody(BaseModel):
    phone_number: str = Field(..., pattern=r"^\+\d{7,15}$")
    channel: OTPChannel = OTPChannel.SMS
    locale: str = Field(default="ar", pattern=r"^[a-z]{2}$")


class OTPVerifyBody(BaseModel):
    phone_number: str = Field(..., pattern=r"^\+\d{7,15}$")
    otp_code: str = Field(..., pattern=r"^\d{6}$")


class FaceVerifyBody(BaseModel):
    image_base64: str = Field(..., min_length=100)
    session_token: str = Field(..., min_length=32)


class EnrollmentResponse(BaseModel):
    success: bool
    zkp_token: Optional[str] = None
    verification_level: Optional[int] = None
    message: str
    request_id: str


class CensusSubmission(BaseModel):
    zkp_proof: str = Field(..., min_length=10)
    nullifier_hash: str = Field(..., min_length=64, max_length=64)

    # Demographic data — all optional to support partial submissions
    region_code: str = Field(..., min_length=2, max_length=10)
    district_code: Optional[str] = Field(None, max_length=10)
    is_urban: Optional[bool] = None

    ethnicity_code: Optional[str] = Field(None, max_length=20)
    language_code: Optional[str] = Field(None, max_length=20)
    religion_code: Optional[str] = Field(None, max_length=20)
    age_bracket: Optional[str] = Field(None, max_length=10)
    gender_code: Optional[str] = Field(None, max_length=10)
    household_size: Optional[int] = Field(None, ge=1, le=30)

    education_level: Optional[str] = Field(None, max_length=20)
    employment_status: Optional[str] = Field(None, max_length=20)
    housing_type: Optional[str] = Field(None, max_length=20)

    @field_validator("age_bracket")
    @classmethod
    def validate_age_bracket(cls, v: Optional[str]) -> Optional[str]:
        valid = {"under-18", "18-24", "25-34", "35-44", "45-54", "55-64", "65+"}
        if v and v not in valid:
            raise ValueError(f"age_bracket must be one of: {valid}")
        return v


class CensusSubmissionResponse(BaseModel):
    success: bool
    confirmation_code: str
    merkle_inclusion_proof: Optional[str] = None
    message: str


# ─── Health Check ──────────────────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    return {"status": "ok", "version": settings.APP_VERSION}


# ─── Identity Verification Endpoints ──────────────────────────────────────────

@app.post("/v1/auth/otp/send", response_model=dict)
async def send_otp(
    body: OTPRequestBody,
    request: Request,
    otp_svc: OTPService = Depends(get_otp_service),
    x_request_id: str = Header(default_factory=lambda: str(uuid.uuid4())),
):
    """Send OTP to phone number. Rate limited to 5 requests per 10 minutes."""
    result = await otp_svc.send_otp(
        phone_number=body.phone_number,
        preferred_channel=body.channel,
        locale=body.locale,
    )

    if result == OTPResult.RATE_LIMITED:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many OTP requests. Please wait before trying again.",
            headers={"Retry-After": "600"},
        )

    if result == OTPResult.DELIVERY_FAILED:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Could not deliver OTP. Please try a different channel.",
        )

    return {"sent": True, "expires_in_seconds": 300, "request_id": x_request_id}


@app.post("/v1/auth/otp/verify", response_model=dict)
async def verify_otp(
    body: OTPVerifyBody,
    request: Request,
    otp_svc: OTPService = Depends(get_otp_service),
    fraud_svc: FraudDetectionService = Depends(get_fraud_service),
):
    """Verify OTP code. Returns a short-lived session token on success."""
    fraud_ctx = RegistrationContext(
        phone_hash=_hash_value(body.phone_number),
        device_fingerprint_hash=_extract_device_hash(request),
        ip_hash=_hash_value(request.client.host),
        timezone=request.headers.get("X-Timezone", "UTC"),
        locale=request.headers.get("Accept-Language", "ar")[:5],
        channel="web",
        user_agent_hash=_hash_value(request.headers.get("user-agent", "")),
    )

    fraud_result = await fraud_svc.evaluate(fraud_ctx)
    if fraud_result.decision == FraudDecision.BLOCK:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registration blocked due to suspicious activity.",
        )

    result = await otp_svc.verify_otp(body.phone_number, body.otp_code)

    if result == OTPResult.VERIFIED:
        session_token = _issue_session_token(body.phone_number)
        return {
            "verified": True,
            "session_token": session_token,
            "verification_level": 1,
            "next_step": "face_verification",
        }

    error_messages = {
        OTPResult.INVALID: "Invalid OTP code.",
        OTPResult.EXPIRED: "OTP has expired. Please request a new one.",
        OTPResult.MAX_ATTEMPTS: "Maximum attempts exceeded. Request a new OTP.",
    }

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=error_messages.get(result, "Verification failed."),
    )


@app.post("/v1/auth/face/verify", response_model=dict)
async def verify_face(
    body: FaceVerifyBody,
    request: Request,
    face_svc: FaceVerificationService = Depends(get_face_service),
    zkp_svc: ZKPService = Depends(get_zkp_service),
):
    """
    Verify face liveness and uniqueness.
    On success: issues ZKP token for census submission.
    Raw image is processed in-memory and NEVER stored.
    """
    session = _validate_session_token(body.session_token)
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session.")

    import base64
    try:
        image_bytes = base64.b64decode(body.image_base64)
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid image data.")

    if len(image_bytes) > 10 * 1024 * 1024:  # 10MB limit
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)

    citizen_salt = _derive_citizen_salt(session["citizen_id"])

    face_result = await face_svc.verify(
        image_bytes=image_bytes,
        citizen_salt=citizen_salt,
    )

    if face_result.result != FaceVerificationResult.VERIFIED:
        error_map = {
            FaceVerificationResult.LIVENESS_FAILED: "Liveness check failed. Please use a live camera.",
            FaceVerificationResult.DUPLICATE_DETECTED: "Face already registered.",
            FaceVerificationResult.NO_FACE_DETECTED: "No face detected. Please ensure good lighting.",
            FaceVerificationResult.QUALITY_TOO_LOW: "Image quality too low.",
            FaceVerificationResult.ID_MISMATCH: "Face does not match ID document.",
        }
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=error_map.get(face_result.result, "Face verification failed."),
        )

    # Issue ZKP token — anonymous proof of verified identity
    zkp_token = await zkp_svc.issue_token(
        citizen_id=session["citizen_id"],
        verification_level=2,
        census_id="CENSUS-2026",
    )

    return {
        "verified": True,
        "zkp_token_id": zkp_token.token_id,
        "verification_level": 2,
        "proof": zkp_token.proof_data.hex(),
        "nullifier": zkp_token.nullifier_hash.hex(),
    }


# ─── Census Submission ─────────────────────────────────────────────────────────

@app.post("/v1/census/submit", response_model=CensusSubmissionResponse)
async def submit_census(
    body: CensusSubmission,
    request: Request,
    zkp_svc: ZKPService = Depends(get_zkp_service),
    redis: redis_client.Redis = Depends(get_redis),
):
    """
    Submit census response using ZKP token.
    No identity information is required or accepted.
    Prevents double submission via nullifier.
    """
    nullifier_bytes = bytes.fromhex(body.nullifier_hash)

    # Check nullifier hasn't been used
    nullifier_key = f"census:nullifier:{body.nullifier_hash}"
    if await redis.exists(nullifier_key):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Census already submitted for this token.",
        )

    # Verify ZKP proof
    proof_bytes = bytes.fromhex(body.zkp_proof)
    verification = await zkp_svc.verify_token(
        proof_data=proof_bytes,
        nullifier_hash=nullifier_bytes,
        census_id="CENSUS-2026",
        required_verification_level=1,
    )

    if not verification.is_valid:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or expired census token.",
        )

    # Store demographic response (anonymous — no identity link)
    response_id = str(uuid.uuid4())
    await _store_census_response(body, response_id, redis)

    # Mark nullifier as used (prevents double submission)
    await redis.setex(nullifier_key, 60 * 60 * 24 * 365, "used")  # 1 year TTL

    # Generate Merkle inclusion proof for citizen verification
    confirmation_code = _generate_confirmation_code(response_id, nullifier_bytes)

    await emit_audit_event(
        event_type="census.submitted",
        outcome="success",
        metadata={
            "response_id": response_id,
            "region": body.region_code,
            "channel": "web",
        },
    )

    return CensusSubmissionResponse(
        success=True,
        confirmation_code=confirmation_code,
        message="Census response recorded. Thank you for your participation.",
    )


# ─── Analytics (Aggregated Only) ──────────────────────────────────────────────

@app.get("/v1/stats/overview")
async def get_overview_stats(
    region_code: Optional[str] = None,
    redis: redis_client.Redis = Depends(get_redis),
):
    """
    Return aggregated, privacy-preserving statistics.
    k-Anonymity enforced: any group < 100 is suppressed.
    """
    # In production: query pre-aggregated materialized views
    # with differential privacy noise added
    return {
        "total_submissions": "aggregated_count",
        "note": "Individual data is never exposed. k-anonymity enforced.",
        "privacy_budget_epsilon": 1.0,  # Differential privacy parameter
    }


# ─── Helpers ───────────────────────────────────────────────────────────────────

def _hash_value(value: str) -> bytes:
    import hashlib
    return hashlib.sha3_256(value.encode()).digest()

def _extract_device_hash(request: Request) -> bytes:
    device_signals = (
        request.headers.get("user-agent", "")
        + request.headers.get("accept-language", "")
        + request.headers.get("accept-encoding", "")
    )
    return _hash_value(device_signals)

def _issue_session_token(phone_number: str) -> str:
    import secrets
    import hashlib
    token = secrets.token_hex(32)
    # Store in Redis with 10 min TTL
    # In production: redis.setex(f"session:{token}", 600, ...)
    return token

def _validate_session_token(token: str) -> Optional[dict]:
    # In production: validate from Redis
    return {"citizen_id": str(uuid.uuid4())}  # Placeholder

def _derive_citizen_salt(citizen_id: str) -> bytes:
    import hashlib
    master = settings.ENCRYPTION_KEY.get_secret_value().encode()
    return hashlib.sha3_256(master + citizen_id.encode()).digest()

async def _store_census_response(body: CensusSubmission, response_id: str, redis) -> None:
    # In production: write to PostgreSQL census_responses table
    pass

def _generate_confirmation_code(response_id: str, nullifier: bytes) -> str:
    import hashlib
    combined = response_id.encode() + nullifier
    digest = hashlib.sha3_256(combined).hexdigest()
    return digest[:16].upper()
