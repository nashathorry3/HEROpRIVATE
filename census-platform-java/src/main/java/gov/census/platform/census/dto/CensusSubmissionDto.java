package gov.census.platform.census.dto;

import jakarta.validation.constraints.*;

public record CensusSubmissionDto(

        // ─── ZKP Proof (Anonymous Identity Credential) ─────────────────────
        @NotBlank
        String zkpProof,

        @NotBlank
        @Size(min = 64, max = 64, message = "Nullifier must be 64 hex characters")
        @Pattern(regexp = "^[0-9a-f]{64}$", message = "Nullifier must be lowercase hex")
        String nullifierHash,

        // ─── Geographic ────────────────────────────────────────────────────
        @NotBlank
        @Size(min = 2, max = 10)
        String regionCode,

        @Size(max = 10)
        String districtCode,

        Boolean isUrban,

        // ─── Demographic (all optional — voluntary) ────────────────────────
        @Size(max = 20)
        String ethnicityCode,

        @Size(max = 20)
        String languageCode,

        @Size(max = 20)
        String religionCode,

        @Pattern(
            regexp = "^(under-18|18-24|25-34|35-44|45-54|55-64|65\\+)$",
            message = "Invalid age bracket"
        )
        String ageBracket,

        @Size(max = 10)
        String genderCode,

        @Min(1) @Max(30)
        Integer householdSize,

        // ─── Socioeconomic (optional) ────────────────────────────────────
        @Size(max = 20)
        String educationLevel,

        @Size(max = 20)
        String employmentStatus,

        @Size(max = 20)
        String housingType
) {}
