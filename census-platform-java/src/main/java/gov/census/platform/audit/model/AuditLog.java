package gov.census.platform.audit.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.Immutable;

import java.time.Instant;
import java.util.Map;

/**
 * Immutable audit log entry.
 * @Immutable tells Hibernate: never issue UPDATE statements.
 * Database-level prevention via trigger (see migration V3).
 */
@Entity
@Immutable
@Table(name = "audit_log", schema = "audit",
        indexes = {
                @Index(name = "idx_audit_event_type", columnList = "event_type"),
                @Index(name = "idx_audit_event_time", columnList = "event_time"),
                @Index(name = "idx_audit_outcome", columnList = "outcome")
        })
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "event_type", nullable = false, length = 50)
    private String eventType;

    @CreationTimestamp
    @Column(name = "event_time", nullable = false, updatable = false)
    private Instant eventTime;

    @Column(name = "actor_type", length = 20)
    private String actorType;

    @Column(name = "actor_hash", columnDefinition = "bytea")
    private byte[] actorHash;

    @Column(name = "outcome", nullable = false, length = 10)
    private String outcome;

    @Column(name = "risk_score")
    private Double riskScore;

    @ElementCollection
    @CollectionTable(name = "audit_log_metadata", schema = "audit",
            joinColumns = @JoinColumn(name = "audit_log_id"))
    @MapKeyColumn(name = "key")
    @Column(name = "value")
    private Map<String, Object> metadata;

    // HMAC-SHA256 of event content — detects tampering
    @Column(name = "signature", nullable = false, columnDefinition = "bytea")
    private byte[] signature;
}
