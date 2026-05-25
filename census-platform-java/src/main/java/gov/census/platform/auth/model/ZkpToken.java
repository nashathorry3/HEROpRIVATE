package gov.census.platform.auth.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.UUID;

/**
 * Anonymous ZKP token.
 * Links to NO identity data — the cryptographic proof IS the credential.
 * nullifier_hash is unique per (citizen, census) — prevents double-use.
 */
@Entity
@Table(name = "zkp_tokens", schema = "identity",
        indexes = @Index(name = "idx_zkp_nullifier", columnList = "nullifier_hash", unique = true))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ZkpToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID tokenId;

    // Unique per (citizen, census) — the only linkage control
    @Column(name = "nullifier_hash", nullable = false, unique = true, columnDefinition = "bytea")
    private byte[] nullifierHash;

    @Column(name = "proof_data", nullable = false, columnDefinition = "bytea")
    private byte[] proofData;

    @Column(name = "circuit_version", nullable = false, length = 10)
    private String circuitVersion;

    @Column(name = "verification_level", nullable = false)
    private int verificationLevel;

    @CreationTimestamp
    @Column(name = "issued_at", updatable = false)
    private Instant issuedAt;

    @Column(name = "census_used")
    private boolean censusUsed = false;

    @Column(name = "census_used_at")
    private Instant censusUsedAt;
}
