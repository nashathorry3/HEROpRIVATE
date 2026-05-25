package gov.census.platform.auth.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "devices", schema = "identity",
        indexes = @Index(name = "idx_device_fingerprint", columnList = "fingerprint_hash"))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Device {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "fingerprint_hash", nullable = false, columnDefinition = "bytea")
    private byte[] fingerprintHash;

    @Column(name = "risk_score", precision = 3, scale = 2)
    private BigDecimal riskScore = BigDecimal.ZERO;

    @CreationTimestamp
    @Column(name = "first_seen", updatable = false)
    private Instant firstSeen;

    @UpdateTimestamp
    @Column(name = "last_seen")
    private Instant lastSeen;

    @Column(name = "registration_count")
    private int registrationCount = 0;

    @Column(name = "is_blocked")
    private boolean blocked = false;

    @Column(name = "block_reason", length = 100)
    private String blockReason;
}
