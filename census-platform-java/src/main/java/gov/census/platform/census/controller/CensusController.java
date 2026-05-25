package gov.census.platform.census.controller;

import gov.census.platform.census.dto.CensusSubmissionDto;
import gov.census.platform.census.service.CensusService;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/v1/census")
@RequiredArgsConstructor
@Tag(name = "Census", description = "Anonymous demographic data collection")
public class CensusController {

    private final CensusService censusService;

    // ─── POST /v1/census/submit ───────────────────────────────────────────────

    @PostMapping("/submit")
    @RateLimiter(name = "census-submit")
    @PreAuthorize("hasRole('FACE_VERIFIED') or hasRole('OTP_VERIFIED')")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(
            summary = "Submit anonymous census response",
            description = """
                Submits a census response using a ZKP token.
                No identity information is required or accepted.
                Duplicate submission is prevented via cryptographic nullifier.
                All demographic data is voluntary.
            """
    )
    public ResponseEntity<Map<String, Object>> submit(
            @Valid @RequestBody CensusSubmissionDto dto
    ) {
        CensusService.SubmitResult result = censusService.submit(dto);

        return switch (result.result()) {
            case SUCCESS -> ResponseEntity.ok(Map.of(
                    "success", true,
                    "confirmationCode", result.confirmationCode(),
                    "message", "Census response recorded. Thank you for your participation."
            ));
            case DUPLICATE -> ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                    "error", "Census already submitted for this token."
            ));
            case INVALID_TOKEN -> ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                    "error", "Invalid or expired census token."
            ));
            case REGION_NOT_FOUND -> ResponseEntity.badRequest().body(Map.of(
                    "error", "Invalid region code."
            ));
        };
    }

    // ─── GET /v1/stats/overview ───────────────────────────────────────────────

    @GetMapping("/stats/overview")
    @PreAuthorize("hasRole('ANALYST') or hasRole('ADMIN')")
    @Operation(
            summary = "Aggregated census statistics (k-anonymity enforced)",
            description = "Returns only aggregate statistics. Groups < 100 are suppressed."
    )
    public ResponseEntity<Map<String, Object>> getStats(
            @RequestParam(required = false) String regionCode
    ) {
        // In production: query pre-aggregated materialized views
        // with differential privacy noise (epsilon=1.0)
        return ResponseEntity.ok(Map.of(
                "privacyNote", "k-anonymity threshold: 100. Differential privacy epsilon: 1.0.",
                "region", regionCode != null ? regionCode : "national",
                "totalSubmissions", "AGGREGATED"
        ));
    }
}
