package gov.census.platform.audit.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import gov.census.platform.audit.model.AuditLog;
import gov.census.platform.audit.repository.AuditLogRepository;
import gov.census.platform.common.config.AppProperties;
import gov.census.platform.common.util.HashUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

/**
 * Immutable audit trail.
 * Every security event is:
 *  1. Written to Kafka (durable, ordered)
 *  2. Consumed by AuditWriter → PostgreSQL (append-only)
 *  3. HMAC-signed to detect tampering
 *
 * Non-blocking: uses @Async to avoid slowing down the main request.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuditService {

    private final KafkaTemplate<String, AuditLog> kafkaTemplate;
    private final AppProperties props;
    private final ObjectMapper objectMapper;

    // PII fields that must never appear in audit metadata
    private static final Set<String> PII_KEYS = Set.of(
            "name", "phone", "email", "address", "dob",
            "national_id", "passport", "face_image", "embedding"
    );

    @Async
    public void emit(
            String eventType,
            String outcome,
            byte[] actorHash,
            Map<String, Object> metadata
    ) {
        try {
            Map<String, Object> sanitized = sanitize(metadata);
            String content = buildSignatureContent(eventType, outcome, actorHash, sanitized);
            byte[] signature = HashUtil.hmacSha256(
                    props.getSecurity().getCrypto().getHmacSecret(), content
            );

            AuditLog entry = AuditLog.builder()
                    .eventType(eventType)
                    .eventTime(Instant.now())
                    .actorType("system")
                    .actorHash(actorHash)
                    .outcome(outcome)
                    .metadata(sanitized)
                    .signature(signature)
                    .build();

            kafkaTemplate.send(
                    props.getKafka() != null ? "census.audit.events" : "census.audit.events",
                    eventType,
                    entry
            );
        } catch (Exception e) {
            // Audit failures must not break the main flow — log and continue
            log.error("Failed to emit audit event [{}]: {}", eventType, e.getMessage());
        }
    }

    private String buildSignatureContent(
            String eventType, String outcome, byte[] actorHash, Map<String, Object> metadata
    ) {
        return String.format("%s|%s|%s|%d",
                eventType,
                outcome,
                actorHash != null ? HashUtil.toHex(actorHash) : "null",
                Instant.now().getEpochSecond()
        );
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> sanitize(Map<String, Object> metadata) {
        if (metadata == null) return Map.of();
        return metadata.entrySet().stream()
                .collect(java.util.stream.Collectors.toMap(
                        Map.Entry::getKey,
                        e -> PII_KEYS.contains(e.getKey().toLowerCase())
                                ? "[REDACTED]"
                                : e.getValue()
                ));
    }
}
