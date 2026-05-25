package gov.census.platform.auth.service;

import gov.census.platform.audit.service.AuditService;
import gov.census.platform.auth.model.OtpSession;
import gov.census.platform.auth.repository.OtpSessionRepository;
import gov.census.platform.common.config.AppProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("OtpService")
class OtpServiceTest {

    @Mock private OtpSessionRepository otpSessionRepo;
    @Mock private StringRedisTemplate redis;
    @Mock private ValueOperations<String, String> valueOps;
    @Mock private AuditService auditService;

    private OtpService otpService;
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(4); // low cost for tests

    @BeforeEach
    void setUp() {
        AppProperties props = buildTestProps();
        otpService = new OtpService(otpSessionRepo, props, passwordEncoder, redis, auditService);
        when(redis.opsForValue()).thenReturn(valueOps);
    }

    @Nested
    @DisplayName("verify()")
    class Verify {

        @Test
        @DisplayName("returns EXPIRED when no session found")
        void returnsExpiredWhenNoSession() {
            when(otpSessionRepo.findByPhoneHash(any())).thenReturn(Optional.empty());

            OtpService.OtpResult result = otpService.verify("+9647001234567", "123456");

            assertThat(result).isEqualTo(OtpService.OtpResult.EXPIRED);
        }

        @Test
        @DisplayName("returns EXPIRED when session is past expiry time")
        void returnsExpiredWhenSessionExpired() {
            OtpSession session = OtpSession.builder()
                    .phoneHash(new byte[32])
                    .otpHash(passwordEncoder.encode("123456"))
                    .expiresAt(Instant.now().minusSeconds(10))
                    .attempts(0)
                    .build();

            when(otpSessionRepo.findByPhoneHash(any())).thenReturn(Optional.of(session));

            OtpService.OtpResult result = otpService.verify("+9647001234567", "123456");

            assertThat(result).isEqualTo(OtpService.OtpResult.EXPIRED);
            verify(otpSessionRepo).delete(session);
        }

        @Test
        @DisplayName("returns MAX_ATTEMPTS when attempts exhausted")
        void returnsMaxAttempts() {
            OtpSession session = OtpSession.builder()
                    .phoneHash(new byte[32])
                    .otpHash(passwordEncoder.encode("999999"))
                    .expiresAt(Instant.now().plusSeconds(300))
                    .attempts(3)
                    .build();

            when(otpSessionRepo.findByPhoneHash(any())).thenReturn(Optional.of(session));

            OtpService.OtpResult result = otpService.verify("+9647001234567", "123456");

            assertThat(result).isEqualTo(OtpService.OtpResult.MAX_ATTEMPTS);
        }

        @Test
        @DisplayName("returns INVALID for wrong OTP code")
        void returnsInvalidForWrongCode() {
            OtpSession session = OtpSession.builder()
                    .phoneHash(new byte[32])
                    .otpHash(passwordEncoder.encode("111111"))
                    .expiresAt(Instant.now().plusSeconds(300))
                    .attempts(0)
                    .build();

            when(otpSessionRepo.findByPhoneHash(any())).thenReturn(Optional.of(session));
            when(otpSessionRepo.save(any())).thenReturn(session);

            OtpService.OtpResult result = otpService.verify("+9647001234567", "999999");

            assertThat(result).isEqualTo(OtpService.OtpResult.INVALID);
            // Attempts incremented before check
            assertThat(session.getAttempts()).isEqualTo(1);
        }

        @Test
        @DisplayName("returns VERIFIED and deletes session on correct code")
        void returnsVerifiedOnCorrectCode() {
            String correctOtp = "654321";
            OtpSession session = OtpSession.builder()
                    .phoneHash(new byte[32])
                    .otpHash(passwordEncoder.encode(correctOtp))
                    .expiresAt(Instant.now().plusSeconds(300))
                    .attempts(0)
                    .build();

            when(otpSessionRepo.findByPhoneHash(any())).thenReturn(Optional.of(session));
            when(otpSessionRepo.save(any())).thenReturn(session);

            OtpService.OtpResult result = otpService.verify("+9647001234567", correctOtp);

            assertThat(result).isEqualTo(OtpService.OtpResult.VERIFIED);
            verify(otpSessionRepo).delete(session);  // Session deleted after success
        }
    }

    @Nested
    @DisplayName("send() — rate limiting")
    class RateLimiting {

        @Test
        @DisplayName("returns RATE_LIMITED when threshold exceeded")
        void returnsRateLimitedWhenThresholdExceeded() {
            when(valueOps.increment(anyString())).thenReturn(6L); // > maxRequests=5

            OtpService.OtpResult result = otpService.send(
                    "+9647001234567", OtpService.OtpChannel.SMS, "ar"
            );

            assertThat(result).isEqualTo(OtpService.OtpResult.RATE_LIMITED);
            verifyNoInteractions(otpSessionRepo);
        }
    }

    private AppProperties buildTestProps() {
        AppProperties props = new AppProperties();
        AppProperties.Security security = new AppProperties.Security();
        AppProperties.Security.Otp otp = new AppProperties.Security.Otp();
        otp.setTtlSeconds(300);
        otp.setMaxAttempts(3);
        otp.setRateLimitWindowSeconds(600);
        otp.setRateLimitMaxRequests(5);
        security.setOtp(otp);

        AppProperties.Security.Crypto crypto = new AppProperties.Security.Crypto();
        crypto.setGlobalPhoneSalt("test-salt-for-unit-tests");
        crypto.setEncryptionKey("test-encryption-key-32-chars!!!!!");
        crypto.setHmacSecret("test-hmac-secret-for-unit-tests!!");
        security.setCrypto(crypto);
        props.setSecurity(security);

        AppProperties.Twilio twilio = new AppProperties.Twilio();
        twilio.setAccountSid("ACtest");
        twilio.setAuthToken("test-token");
        twilio.setFromNumber("+1234567890");
        props.setTwilio(twilio);

        return props;
    }
}
