package gov.census.platform.auth.service;

import gov.census.platform.audit.service.AuditService;
import gov.census.platform.common.config.AppProperties;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;

/**
 * Multi-layer fraud detection.
 * Layer 1: Fast Redis-backed rules (< 10ms)
 * Layer 2: Weighted score model
 * Layer 3: Async graph analysis (via Kafka event)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class FraudDetectionService {

    private final StringRedisTemplate redis;
    private final AppProperties props;
    private final AuditService auditService;

    public enum Decision { ALLOW, REVIEW, BLOCK, CHALLENGE }

    @Builder
    public record RegistrationContext(
            byte[] phoneHash,
            byte[] deviceFingerprintHash,
            byte[] ipHash,
            String timezone,
            String locale,
            String channel,
            double typingRhythmScore,   // 0.0 = bot, 1.0 = human
            boolean hasTypingData
    ) {}

    @Builder
    public record FraudSignals(
            double ipVelocityScore,
            int deviceReuseCount,
            double behavioralAnomalyScore,
            double timePatternScore
    ) {}

    public record EvaluationResult(
            Decision decision,
            double overallScore,
            FraudSignals signals,
            String reason
    ) {}

    // ─── Main Evaluation ─────────────────────────────────────────────────────

    public EvaluationResult evaluate(RegistrationContext ctx) {
        String ipKey     = "fraud:ip:" + toHex(ctx.ipHash());
        String deviceKey = "fraud:device:" + toHex(ctx.deviceFingerprintHash());
        String timeKey   = "fraud:timing:" + toHex(ctx.ipHash());

        // Rule 1: IP velocity
        long ipCount = incrementRedis(ipKey, Duration.ofHours(1));
        double ipScore = Math.min(ipCount / 10.0, 1.0);

        if (ipCount > 10) {
            return blockResult(FraudSignals.builder()
                    .ipVelocityScore(ipScore).build(), "ip_velocity_exceeded");
        }

        // Rule 2: Device reuse — one device = one registration
        long deviceCount = incrementRedis(deviceKey, Duration.ofHours(24));
        if (deviceCount > 1) {
            auditService.emit("fraud.device_reuse", "blocked", ctx.deviceFingerprintHash(),
                    Map.of("count", deviceCount));
            return blockResult(FraudSignals.builder()
                    .deviceReuseCount((int) deviceCount).build(), "device_reuse");
        }

        // Rule 3: Timing pattern (bot detection < 2s between requests)
        String lastTimeStr = redis.opsForValue().get(timeKey);
        double now = System.currentTimeMillis() / 1000.0;
        redis.opsForValue().set(timeKey, String.valueOf(now), Duration.ofHours(1));

        double timeScore = 1.0;
        if (lastTimeStr != null) {
            double interval = now - Double.parseDouble(lastTimeStr);
            if (interval < 2.0) {
                return blockResult(FraudSignals.builder()
                        .timePatternScore(0.1).build(), "bot_timing_pattern");
            }
            timeScore = Math.min(interval / 30.0, 1.0);
        }

        // Rule 4: Behavioral (typing dynamics)
        double behavioralScore = 0.0;
        if (ctx.hasTypingData()) {
            behavioralScore = 1.0 - ctx.typingRhythmScore();
            if (ctx.typingRhythmScore() < 0.3) {
                return EvaluationResult(Decision.CHALLENGE, 0.7,
                        FraudSignals.builder().behavioralAnomalyScore(behavioralScore).build(),
                        "behavioral_anomaly");
            }
        }

        FraudSignals signals = FraudSignals.builder()
                .ipVelocityScore(ipScore)
                .deviceReuseCount((int) deviceCount)
                .behavioralAnomalyScore(behavioralScore)
                .timePatternScore(timeScore)
                .build();

        double overall = computeScore(signals);
        Decision decision = decideFromScore(overall);

        auditService.emit("fraud." + decision.name().toLowerCase(), "evaluated",
                ctx.deviceFingerprintHash(),
                Map.of("score", overall, "decision", decision.name()));

        return new EvaluationResult(decision, overall, signals,
                decision == Decision.ALLOW ? null : "score_" + String.format("%.2f", overall));
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private long incrementRedis(String key, Duration ttl) {
        Long count = redis.opsForValue().increment(key);
        if (count != null && count == 1) {
            redis.expire(key, ttl);
        }
        return count == null ? 0 : count;
    }

    private double computeScore(FraudSignals s) {
        double score =
                s.ipVelocityScore() * 0.20
                + (s.deviceReuseCount() > 0 ? 1.0 : 0.0) * 0.30
                + s.behavioralAnomalyScore() * 0.25
                + (1.0 - s.timePatternScore()) * 0.25;
        return Math.min(Math.max(score, 0.0), 1.0);
    }

    private Decision decideFromScore(double score) {
        if (score >= props.getFraud().getBlockThreshold())  return Decision.BLOCK;
        if (score >= props.getFraud().getReviewThreshold()) return Decision.REVIEW;
        return Decision.ALLOW;
    }

    private EvaluationResult blockResult(FraudSignals signals, String reason) {
        return new EvaluationResult(Decision.BLOCK, 1.0, signals, reason);
    }

    private EvaluationResult EvaluationResult(Decision d, double score, FraudSignals s, String r) {
        return new EvaluationResult(d, score, s, r);
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
