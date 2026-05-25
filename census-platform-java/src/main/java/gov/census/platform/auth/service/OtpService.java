package gov.census.platform.auth.service;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import gov.census.platform.audit.service.AuditService;
import gov.census.platform.auth.model.OtpSession;
import gov.census.platform.auth.repository.OtpSessionRepository;
import gov.census.platform.common.config.AppProperties;
import gov.census.platform.common.util.HashUtil;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class OtpService {

    private final OtpSessionRepository otpSessionRepo;
    private final AppProperties props;
    private final PasswordEncoder passwordEncoder;
    private final StringRedisTemplate redis;
    private final AuditService auditService;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @PostConstruct
    void initTwilio() {
        Twilio.init(
            props.getTwilio().getAccountSid(),
            props.getTwilio().getAuthToken()
        );
    }

    public enum OtpResult { SENT, VERIFIED, INVALID, EXPIRED, MAX_ATTEMPTS, RATE_LIMITED, DELIVERY_FAILED }
    public enum OtpChannel { SMS, WHATSAPP, VOICE }

    // ─── Send OTP ────────────────────────────────────────────────────────────

    @Transactional
    public OtpResult send(String phoneNumber, OtpChannel channel, String locale) {
        byte[] phoneHash = hashPhone(phoneNumber);
        String rateLimitKey = "otp:ratelimit:" + HashUtil.toHex(phoneHash);

        if (isRateLimited(rateLimitKey)) {
            auditService.emit("otp.rate_limited", "blocked", phoneHash, null);
            return OtpResult.RATE_LIMITED;
        }

        // Invalidate any existing session for this phone
        otpSessionRepo.deleteByPhoneHash(phoneHash);

        String rawOtp = generateOtp();
        String otpHash = passwordEncoder.encode(rawOtp);  // bcrypt cost=12

        AppProperties.Security.Otp otpCfg = props.getSecurity().getOtp();
        OtpSession session = OtpSession.builder()
                .phoneHash(phoneHash)
                .otpHash(otpHash)
                .expiresAt(Instant.now().plusSeconds(otpCfg.getTtlSeconds()))
                .build();

        otpSessionRepo.save(session);

        try {
            deliver(phoneNumber, rawOtp, channel, locale);
        } catch (Exception e) {
            log.warn("OTP delivery failed via {}: {}", channel, e.getMessage());
            // Try fallback channels
            for (OtpChannel fallback : OtpChannel.values()) {
                if (fallback == channel) continue;
                try {
                    deliver(phoneNumber, rawOtp, fallback, locale);
                    break;
                } catch (Exception ex) {
                    log.warn("OTP fallback delivery failed via {}", fallback);
                }
            }
        }

        incrementRateLimit(rateLimitKey, otpCfg.getRateLimitWindowSeconds());
        auditService.emit("otp.sent", "success", phoneHash, Map.of("channel", channel.name()));
        return OtpResult.SENT;
    }

    // ─── Verify OTP ──────────────────────────────────────────────────────────

    @Transactional
    public OtpResult verify(String phoneNumber, String otpCode) {
        byte[] phoneHash = hashPhone(phoneNumber);
        AppProperties.Security.Otp otpCfg = props.getSecurity().getOtp();

        Optional<OtpSession> sessionOpt = otpSessionRepo.findByPhoneHash(phoneHash);

        if (sessionOpt.isEmpty()) {
            return OtpResult.EXPIRED;
        }

        OtpSession session = sessionOpt.get();

        if (session.isExpired()) {
            otpSessionRepo.delete(session);
            return OtpResult.EXPIRED;
        }

        if (session.hasMaxAttempts(otpCfg.getMaxAttempts())) {
            otpSessionRepo.delete(session);
            auditService.emit("otp.max_attempts", "blocked", phoneHash, null);
            return OtpResult.MAX_ATTEMPTS;
        }

        // Increment BEFORE check — prevents timing oracle attacks
        session.setAttempts(session.getAttempts() + 1);
        otpSessionRepo.save(session);

        if (!passwordEncoder.matches(otpCode, session.getOtpHash())) {
            auditService.emit("otp.invalid", "failure", phoneHash,
                    Map.of("attempts", session.getAttempts()));
            return OtpResult.INVALID;
        }

        // Success — delete session immediately
        otpSessionRepo.delete(session);
        auditService.emit("otp.verified", "success", phoneHash, null);
        return OtpResult.VERIFIED;
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private String generateOtp() {
        return String.format("%06d", SECURE_RANDOM.nextInt(900000) + 100000);
    }

    private byte[] hashPhone(String phoneNumber) {
        String salt = props.getSecurity().getCrypto().getGlobalPhoneSalt();
        return HashUtil.sha3Hash(salt, phoneNumber);
    }

    private boolean isRateLimited(String key) {
        Long count = redis.opsForValue().increment(key);
        if (count != null && count == 1) {
            redis.expire(key, Duration.ofSeconds(
                    props.getSecurity().getOtp().getRateLimitWindowSeconds()
            ));
        }
        return count != null && count > props.getSecurity().getOtp().getRateLimitMaxRequests();
    }

    private void incrementRateLimit(String key, int windowSeconds) {
        Long count = redis.opsForValue().increment(key);
        if (count != null && count == 1) {
            redis.expire(key, Duration.ofSeconds(windowSeconds));
        }
    }

    private void deliver(String phoneNumber, String otp, OtpChannel channel, String locale) {
        String message = formatMessage(otp, locale);
        String from = props.getTwilio().getFromNumber();

        switch (channel) {
            case SMS -> Message.creator(
                    new PhoneNumber(phoneNumber),
                    new PhoneNumber(from),
                    message
            ).create();

            case WHATSAPP -> Message.creator(
                    new PhoneNumber("whatsapp:" + phoneNumber),
                    new PhoneNumber("whatsapp:" + from),
                    message
            ).create();

            case VOICE -> {
                // Twilio Calls API — TwiML voice read
                com.twilio.rest.api.v2010.account.Call.creator(
                        new PhoneNumber(phoneNumber),
                        new PhoneNumber(from),
                        new com.twilio.type.Twiml(
                                "<Response><Say language='ar'>" + otp + "</Say></Response>"
                        )
                ).create();
            }
        }
    }

    private String formatMessage(String otp, String locale) {
        return switch (locale) {
            case "ar" -> "رمز التحقق الخاص بك: " + otp + "\nصالح 5 دقائق. لا تشاركه.";
            case "ku" -> "کۆدی تایبەتت: " + otp + "\n5 خولەک کارا دەبێت.";
            default  -> "Your verification code: " + otp + "\nValid 5 minutes. Never share it.";
        };
    }
}
