package gov.census.platform.census.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

/**
 * Anonymous demographic census record.
 * Stored in the CENSUS DB — completely separate from Identity DB.
 * Contains NO identity information whatsoever.
 * token_nullifier is the only link — and it's one-way.
 */
@Entity
@Table(name = "census_responses", schema = "census",
        uniqueConstraints = @UniqueConstraint(
                name = "uq_census_nullifier", columnNames = "token_nullifier"
        ))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CensusResponse {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    // One-way nullifier — prevents double-submission, not linkable to identity
    @Column(name = "token_nullifier", nullable = false, unique = true, columnDefinition = "bytea")
    private byte[] tokenNullifier;

    // ─── Geographic (coarsened — district level max, no street address) ───────
    @Column(name = "region_code", nullable = false, length = 10)
    private String regionCode;

    @Column(name = "district_code", length = 10)
    private String districtCode;

    @Column(name = "is_urban")
    private Boolean isUrban;

    // ─── Demographic (self-reported, all optional) ────────────────────────────
    @Column(name = "ethnicity_code", length = 20)
    private String ethnicityCode;

    @Column(name = "language_code", length = 20)   // ISO 639-3
    private String languageCode;

    @Column(name = "religion_code", length = 20)
    private String religionCode;

    @Column(name = "age_bracket", length = 10)
    private String ageBracket;   // '18-24', '25-34', etc. — NOT exact age

    @Column(name = "gender_code", length = 10)
    private String genderCode;

    @Column(name = "household_size")
    private Integer householdSize;

    // ─── Socioeconomic ────────────────────────────────────────────────────────
    @Column(name = "education_level", length = 20)
    private String educationLevel;

    @Column(name = "employment_status", length = 20)
    private String employmentStatus;

    @Column(name = "housing_type", length = 20)
    private String housingType;

    // ─── Submission Metadata (no IP, no device) ───────────────────────────────
    @Column(name = "submission_channel", length = 20)
    private String submissionChannel;  // 'web'|'mobile'|'offline'|'agent'

    @Column(name = "completion_rate", precision = 3, scale = 2)
    private BigDecimal completionRate;

    @Column(name = "response_time_seconds")
    private Integer responseTimeSeconds;

    @CreationTimestamp
    @Column(name = "submitted_at", updatable = false)
    private Instant submittedAt;
}
