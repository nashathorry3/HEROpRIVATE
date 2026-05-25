package gov.census.platform.census.service;

import gov.census.platform.audit.service.AuditService;
import gov.census.platform.auth.service.ZkpService;
import gov.census.platform.census.dto.CensusSubmissionDto;
import gov.census.platform.census.model.CensusResponse;
import gov.census.platform.census.repository.CensusResponseRepository;
import gov.census.platform.common.util.HashUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class CensusService {

    private final CensusResponseRepository censusRepo;
    private final ZkpService zkpService;
    private final AuditService auditService;

    public enum SubmissionResult {
        SUCCESS, DUPLICATE, INVALID_TOKEN, REGION_NOT_FOUND
    }

    @Transactional
    public SubmitResult submit(CensusSubmissionDto dto) {
        byte[] nullifierHash = HashUtil.fromHex(dto.nullifierHash());
        byte[] proofData = HashUtil.fromHex(dto.zkpProof());

        // 1. Verify ZKP token
        ZkpService.VerificationResult zkpResult = zkpService.verify(
                proofData, nullifierHash, 1  // Minimum: phone verification
        );

        if (!zkpResult.valid()) {
            return new SubmitResult(SubmissionResult.INVALID_TOKEN,
                    null, "Invalid or expired census token: " + zkpResult.error());
        }

        // 2. Build anonymous response record
        CensusResponse response = CensusResponse.builder()
                .tokenNullifier(nullifierHash)
                .regionCode(dto.regionCode())
                .districtCode(dto.districtCode())
                .isUrban(dto.isUrban())
                .ethnicityCode(dto.ethnicityCode())
                .languageCode(dto.languageCode())
                .religionCode(dto.religionCode())
                .ageBracket(dto.ageBracket())
                .genderCode(dto.genderCode())
                .householdSize(dto.householdSize())
                .educationLevel(dto.educationLevel())
                .employmentStatus(dto.employmentStatus())
                .housingType(dto.housingType())
                .submissionChannel("web")
                .completionRate(computeCompletionRate(dto))
                .build();

        try {
            censusRepo.save(response);
        } catch (DataIntegrityViolationException e) {
            // Unique constraint on token_nullifier violated — double submission
            return new SubmitResult(SubmissionResult.DUPLICATE,
                    null, "Census already submitted for this token.");
        }

        // 3. Mark ZKP token as used (prevents reuse in this census)
        zkpService.markAsUsed(nullifierHash);

        // 4. Generate confirmation code (tamper-evident, not reversible)
        String confirmationCode = generateConfirmationCode(
                response.getId().toString(), nullifierHash
        );

        auditService.emit("census.submitted", "success", nullifierHash,
                Map.of("region", dto.regionCode(), "id", response.getId().toString()));

        return new SubmitResult(SubmissionResult.SUCCESS, confirmationCode, null);
    }

    private BigDecimal computeCompletionRate(CensusSubmissionDto dto) {
        long optionalFields = 9;  // All demographic + socioeconomic optional fields
        long filled = 0;
        if (dto.isUrban()          != null) filled++;
        if (dto.ethnicityCode()    != null) filled++;
        if (dto.languageCode()     != null) filled++;
        if (dto.religionCode()     != null) filled++;
        if (dto.ageBracket()       != null) filled++;
        if (dto.genderCode()       != null) filled++;
        if (dto.householdSize()    != null) filled++;
        if (dto.educationLevel()   != null) filled++;
        if (dto.employmentStatus() != null) filled++;
        return BigDecimal.valueOf((double) filled / optionalFields);
    }

    private String generateConfirmationCode(String responseId, byte[] nullifier) {
        String content = responseId + HashUtil.toHex(nullifier);
        byte[] hash = HashUtil.sha3Hash("confirmation", content);
        return HashUtil.toHex(hash).substring(0, 16).toUpperCase();
    }

    public record SubmitResult(SubmissionResult result, String confirmationCode, String error) {}
}
