package gov.census.platform.auth.controller;

import gov.census.platform.auth.dto.FaceVerifyDto;
import gov.census.platform.auth.dto.OtpRequestDto;
import gov.census.platform.auth.dto.OtpVerifyDto;
import gov.census.platform.auth.model.ZkpToken;
import gov.census.platform.auth.service.FraudDetectionService;
import gov.census.platform.auth.service.OtpService;
import gov.census.platform.auth.service.ZkpService;
import gov.census.platform.common.security.JwtService;
import gov.census.platform.common.util.HashUtil;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "OTP, face verification, and ZKP token issuance")
public class AuthController {

    private final OtpService otpService;
    private final ZkpService zkpService;
    private final JwtService jwtService;
    private final FraudDetectionService fraudService;

    // ─── POST /v1/auth/otp/send ───────────────────────────────────────────────

    @PostMapping("/otp/send")
    @RateLimiter(name = "otp-send")
    @Operation(summary = "Send OTP to phone number via SMS/WhatsApp/Voice")
    public ResponseEntity<Map<String, Object>> sendOtp(
            @Valid @RequestBody OtpRequestDto body,
            HttpServletRequest request
    ) {
        // Fraud check before sending
        FraudDetectionService.EvaluationResult fraud = fraudService.evaluate(
                buildFraudContext(request, body.phoneNumber())
        );

        if (fraud.decision() == FraudDetectionService.Decision.BLOCK) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Request blocked due to suspicious activity."));
        }

        OtpService.OtpResult result = otpService.send(
                body.phoneNumber(), body.channel(), body.locale()
        );

        return switch (result) {
            case SENT -> ResponseEntity.ok(Map.of(
                    "sent", true,
                    "expiresInSeconds", 300,
                    "requestId", UUID.randomUUID().toString()
            ));
            case RATE_LIMITED -> ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .header("Retry-After", "600")
                    .body(Map.of("error", "Too many requests. Wait 10 minutes."));
            case DELIVERY_FAILED -> ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(Map.of("error", "Could not deliver OTP. Try another channel."));
            default -> ResponseEntity.internalServerError()
                    .body(Map.of("error", "Unexpected error."));
        };
    }

    // ─── POST /v1/auth/otp/verify ─────────────────────────────────────────────

    @PostMapping("/otp/verify")
    @Operation(summary = "Verify OTP code — returns short-lived session JWT on success")
    public ResponseEntity<Map<String, Object>> verifyOtp(
            @Valid @RequestBody OtpVerifyDto body,
            HttpServletRequest request
    ) {
        FraudDetectionService.EvaluationResult fraud = fraudService.evaluate(
                buildFraudContext(request, body.phoneNumber())
        );

        if (fraud.decision() == FraudDetectionService.Decision.BLOCK) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Request blocked."));
        }

        OtpService.OtpResult result = otpService.verify(body.phoneNumber(), body.otpCode());

        return switch (result) {
            case VERIFIED -> {
                String citizenId = UUID.randomUUID().toString(); // Ephemeral per-session ID
                String sessionToken = jwtService.issueSessionToken(
                        citizenId,
                        1,                         // Verification level: phone only
                        List.of("OTP_VERIFIED")
                );
                yield ResponseEntity.ok(Map.of(
                        "verified", true,
                        "sessionToken", sessionToken,
                        "verificationLevel", 1,
                        "nextStep", "face_verification"
                ));
            }
            case INVALID -> ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid OTP code."));
            case EXPIRED -> ResponseEntity.badRequest()
                    .body(Map.of("error", "OTP expired. Request a new one."));
            case MAX_ATTEMPTS -> ResponseEntity.status(HttpStatus.LOCKED)
                    .body(Map.of("error", "Maximum attempts exceeded. Request a new OTP."));
            default -> ResponseEntity.badRequest()
                    .body(Map.of("error", "Verification failed."));
        };
    }

    // ─── POST /v1/auth/face/verify ────────────────────────────────────────────

    @PostMapping("/face/verify")
    @Operation(summary = "Verify face liveness + uniqueness — issues ZKP token on success")
    public ResponseEntity<Map<String, Object>> verifyFace(
            @Valid @RequestBody FaceVerifyDto body,
            @RequestAttribute("citizenId") String citizenId  // Injected by JwtAuthFilter
    ) {
        byte[] imageBytes;
        try {
            imageBytes = Base64.getDecoder().decode(body.imageBase64());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid image data."));
        }

        if (imageBytes.length > 10 * 1024 * 1024) {
            return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
                    .body(Map.of("error", "Image too large."));
        }

        // In production: call face-verification microservice via gRPC
        // Face processing result — mock for now
        boolean faceVerified = callFaceService(imageBytes, citizenId);
        // imageBytes reference dropped immediately — GC will reclaim

        if (!faceVerified) {
            return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY)
                    .body(Map.of("error", "Face verification failed. Ensure good lighting."));
        }

        // Issue ZKP token (anonymous — no identity link)
        ZkpToken token = zkpService.issueToken(citizenId, 2);

        // Upgrade session to face-verified level
        String upgradedToken = jwtService.issueSessionToken(
                citizenId,
                2,
                List.of("OTP_VERIFIED", "FACE_VERIFIED")
        );

        return ResponseEntity.ok(Map.of(
                "verified", true,
                "sessionToken", upgradedToken,
                "zkpTokenId", token.getTokenId().toString(),
                "proof", HashUtil.toHex(token.getProofData()),
                "nullifier", HashUtil.toHex(token.getNullifierHash()),
                "verificationLevel", 2
        ));
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private FraudDetectionService.RegistrationContext buildFraudContext(
            HttpServletRequest request, String phoneNumber
    ) {
        String ip = getClientIp(request);
        String ua = request.getHeader("User-Agent");

        return FraudDetectionService.RegistrationContext.builder()
                .phoneHash(HashUtil.sha3Hash("", phoneNumber))
                .deviceFingerprintHash(HashUtil.sha3Hash("", ua != null ? ua : ""))
                .ipHash(HashUtil.sha3Hash("", ip))
                .timezone(getHeader(request, "X-Timezone", "UTC"))
                .locale(getHeader(request, "Accept-Language", "ar").substring(0, 2))
                .channel("web")
                .hasTypingData(false)
                .build();
    }

    private boolean callFaceService(byte[] imageBytes, String citizenId) {
        // Placeholder — in production: gRPC call to face-verification service
        // The service returns: liveness_score, is_duplicate, face_hash
        return true;
    }

    private String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private String getHeader(HttpServletRequest req, String name, String defaultValue) {
        String val = req.getHeader(name);
        return (val != null && !val.isBlank()) ? val : defaultValue;
    }
}
