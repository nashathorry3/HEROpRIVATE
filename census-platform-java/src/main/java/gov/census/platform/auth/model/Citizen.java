package gov.census.platform.auth.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.UUID;

/**
 * Identity record — stored in the isolated Identity DB.
 * Contains NO demographic data.
 * Real name, raw ID number, and address are NEVER stored.
 */
@Entity
@Table(name = "citizens", schema = "identity",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = "phone_hash"),
                @UniqueConstraint(columnNames = "face_hash"),
                @UniqueConstraint(columnNames = "document_hash"),
                @UniqueConstraint(columnNames = "zkp_token_id")
        })
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Citizen {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    // SHA3(globalSalt + phoneNumber) — same phone always hashes the same
    @Column(name = "phone_hash", nullable = false, length = 32, columnDefinition = "bytea")
    private byte[] phoneHash;

    // SHA3(citizenSalt + faceEmbeddingBytes) — raw image never stored
    @Column(name = "face_hash", length = 32, columnDefinition = "bytea")
    private byte[] faceHash;

    // SHA3(globalSalt + docNumber + docType + issuer) — raw doc number never stored
    @Column(name = "document_hash", length = 32, columnDefinition = "bytea")
    private byte[] documentHash;

    @Enumerated(EnumType.STRING)
    @Column(name = "enrollment_path", nullable = false, length = 20)
    private EnrollmentPath enrollmentPath;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "device_id")
    private Device device;

    // Points to ZKP token — cross-reference is by UUID only, no PII
    @Column(name = "zkp_token_id", nullable = false)
    private UUID zkpTokenId;

    @Column(name = "verification_level", nullable = false)
    @Builder.Default
    private int verificationLevel = 1;  // 1=phone, 2=face+phone, 3=doc+face+phone

    @Column(name = "is_active")
    @Builder.Default
    private boolean active = true;

    @CreationTimestamp
    @Column(name = "enrollment_at", updatable = false)
    private Instant enrollmentAt;

    public enum EnrollmentPath {
        DOCUMENT, PHONE, BIOMETRIC, AGENT
    }
}
