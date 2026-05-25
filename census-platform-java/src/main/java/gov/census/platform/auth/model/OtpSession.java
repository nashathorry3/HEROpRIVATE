package gov.census.platform.auth.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.UUID;

/**
 * Short-lived OTP session.
 * Deleted immediately after successful verification.
 * phone_hash stored instead of raw phone number.
 */
@Entity
@Table(name = "otp_sessions", schema = "identity",
        indexes = @Index(name = "idx_otp_phone_hash", columnList = "phone_hash"))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OtpSession {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "phone_hash", nullable = false, columnDefinition = "bytea")
    private byte[] phoneHash;

    // bcrypt hash of the 6-digit code — raw OTP never stored
    @Column(name = "otp_hash", nullable = false, length = 60)
    private String otpHash;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "attempts")
    @Builder.Default
    private int attempts = 0;

    @Column(name = "verified")
    @Builder.Default
    private boolean verified = false;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public boolean hasMaxAttempts(int maxAttempts) {
        return attempts >= maxAttempts;
    }
}
