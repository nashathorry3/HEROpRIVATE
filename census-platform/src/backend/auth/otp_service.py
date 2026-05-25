"""
Census Platform — OTP Service
Multi-channel OTP delivery with fraud prevention
"""
import secrets
import hashlib
import hmac
import time
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

import bcrypt
import redis.asyncio as redis
from twilio.rest import Client as TwilioClient

from ..core.config import get_settings
from ..core.audit import emit_audit_event

settings = get_settings()


class OTPChannel(str, Enum):
    SMS = "sms"
    WHATSAPP = "whatsapp"
    VOICE = "voice"
    EMAIL = "email"


class OTPResult(str, Enum):
    SENT = "sent"
    VERIFIED = "verified"
    INVALID = "invalid"
    EXPIRED = "expired"
    MAX_ATTEMPTS = "max_attempts"
    RATE_LIMITED = "rate_limited"
    DELIVERY_FAILED = "delivery_failed"


def _hash_phone(phone_number: str) -> bytes:
    """Deterministic phone hash — same input always produces same hash."""
    salt = settings.GLOBAL_PHONE_SALT.get_secret_value().encode()
    return hashlib.sha3_256(salt + phone_number.encode()).digest()


def _generate_otp() -> str:
    """Cryptographically secure 6-digit OTP."""
    return str(secrets.randbelow(900000) + 100000)


def _hash_otp(otp_code: str) -> bytes:
    """bcrypt hash of OTP — slow enough to resist brute-force."""
    return bcrypt.hashpw(otp_code.encode(), bcrypt.gensalt(rounds=10))


def _verify_otp_hash(otp_code: str, stored_hash: bytes) -> bool:
    return bcrypt.checkpw(otp_code.encode(), stored_hash)


class OTPService:
    def __init__(self, redis_client: redis.Redis):
        self._redis = redis_client
        self._twilio = TwilioClient(
            settings.TWILIO_ACCOUNT_SID.get_secret_value(),
            settings.TWILIO_AUTH_TOKEN.get_secret_value(),
        )

    async def _is_rate_limited(self, phone_hash: bytes) -> bool:
        key = f"otp:ratelimit:{phone_hash.hex()}"
        count = await self._redis.incr(key)
        if count == 1:
            await self._redis.expire(key, settings.RATE_LIMIT_WINDOW_SECONDS)
        return count > settings.RATE_LIMIT_MAX_REQUESTS

    async def send_otp(
        self,
        phone_number: str,
        preferred_channel: OTPChannel = OTPChannel.SMS,
        locale: str = "ar",
    ) -> OTPResult:
        phone_hash = _hash_phone(phone_number)

        if await self._is_rate_limited(phone_hash):
            await emit_audit_event(
                event_type="otp.rate_limited",
                actor_hash=phone_hash,
                outcome="blocked",
            )
            return OTPResult.RATE_LIMITED

        otp_code = _generate_otp()
        otp_hash = _hash_otp(otp_code)

        # Store in Redis with TTL
        session_key = f"otp:session:{phone_hash.hex()}"
        session_data = {
            "otp_hash": otp_hash.hex(),
            "attempts": "0",
            "channel": preferred_channel.value,
            "created_at": str(int(time.time())),
        }
        await self._redis.hset(session_key, mapping=session_data)
        await self._redis.expire(session_key, settings.OTP_TTL_SECONDS)

        # Attempt delivery through channels in priority order
        channels = self._build_channel_priority(preferred_channel)
        delivered = False

        for channel in channels:
            try:
                await self._deliver_otp(phone_number, otp_code, channel, locale)
                delivered = True
                break
            except Exception:
                continue

        if not delivered:
            await self._redis.delete(session_key)
            return OTPResult.DELIVERY_FAILED

        await emit_audit_event(
            event_type="otp.sent",
            actor_hash=phone_hash,
            outcome="success",
            metadata={"channel": channel.value},
        )
        return OTPResult.SENT

    async def verify_otp(self, phone_number: str, otp_code: str) -> OTPResult:
        phone_hash = _hash_phone(phone_number)
        session_key = f"otp:session:{phone_hash.hex()}"

        session = await self._redis.hgetall(session_key)
        if not session:
            return OTPResult.EXPIRED

        attempts = int(session[b"attempts"])
        if attempts >= settings.OTP_MAX_ATTEMPTS:
            await self._redis.delete(session_key)
            return OTPResult.MAX_ATTEMPTS

        # Increment attempts before checking (prevents timing oracle)
        await self._redis.hset(session_key, "attempts", str(attempts + 1))

        stored_hash = bytes.fromhex(session[b"otp_hash"].decode())
        if not _verify_otp_hash(otp_code, stored_hash):
            await emit_audit_event(
                event_type="otp.failed",
                actor_hash=phone_hash,
                outcome="failure",
                metadata={"attempts": attempts + 1},
            )
            return OTPResult.INVALID

        # Verified — delete session immediately
        await self._redis.delete(session_key)

        await emit_audit_event(
            event_type="otp.verified",
            actor_hash=phone_hash,
            outcome="success",
        )
        return OTPResult.VERIFIED

    async def _deliver_otp(
        self,
        phone_number: str,
        otp_code: str,
        channel: OTPChannel,
        locale: str,
    ) -> None:
        message = self._format_message(otp_code, locale)

        if channel == OTPChannel.SMS:
            self._twilio.messages.create(
                body=message,
                from_=settings.TWILIO_FROM_NUMBER,
                to=phone_number,
            )
        elif channel == OTPChannel.WHATSAPP:
            self._twilio.messages.create(
                body=message,
                from_=f"whatsapp:{settings.TWILIO_FROM_NUMBER}",
                to=f"whatsapp:{phone_number}",
            )
        elif channel == OTPChannel.VOICE:
            self._twilio.calls.create(
                twiml=f"<Response><Say language='{locale}'>{otp_code}</Say></Response>",
                from_=settings.TWILIO_FROM_NUMBER,
                to=phone_number,
            )

    @staticmethod
    def _build_channel_priority(preferred: OTPChannel) -> list[OTPChannel]:
        all_channels = [OTPChannel.SMS, OTPChannel.WHATSAPP, OTPChannel.VOICE]
        return [preferred] + [c for c in all_channels if c != preferred]

    @staticmethod
    def _format_message(otp_code: str, locale: str) -> str:
        messages = {
            "ar": f"رمز التحقق الخاص بك هو: {otp_code}\nصالح لمدة 5 دقائق. لا تشاركه مع أحد.",
            "ku": f"کۆدی تایبەتت: {otp_code}\n5 خولەک کارا دەبێت.",
            "en": f"Your verification code is: {otp_code}\nValid for 5 minutes. Never share this code.",
        }
        return messages.get(locale, messages["ar"])
