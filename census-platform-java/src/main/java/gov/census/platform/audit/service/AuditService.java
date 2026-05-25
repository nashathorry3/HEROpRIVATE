package gov.census.platform.audit.service;

import gov.census.platform.audit.model.AuditLog;
import gov.census.platform.common.config.AppProperties;
import gov.census.platform.common.util.HashUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.lang.Nullable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Immutable audit trail.
 * Events go to Kafka → PostgreSQL (append-only).
 * Every event is HMAC-signed to detect tampering.
 * Non-blocking: @Async so it never slows down the main request.
 * KafkaTemplate is optional — falls back to structured logging when Kafka unavailable.
 */
@Slf4j
@Service
public class AuditService {

    @Nullable
    private final KafkaTemplate<String, AuditLog> kafkaTemplate;
    private final AppProperties props;

    @Autowired
    public AuditService(@Nullable KafkaTemplate<String, AuditLog> kafkaTemplate,
                        AppProperties props) {
        this.kafkaTemplate = kafkaTemplate;
        this.props = props;
    }

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
            Map<String, String> sanitized = sanitize(metadata);
            String content = String.format("%s|%s|%s|%d",
                    eventType, outcome,
                    actorHash != null ? HashUtil.toHex(actorHash) : "null",
                    Instant.now().getEpochSecond());

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

            if (kafkaTemplate != null) {
                kafkaTemplate.send("census.audit.events", eventType, entry);
            } else {
                log.info("AUDIT [{}] outcome={} actor={}", eventType, outcome,
                        actorHash != null ? HashUtil.toHex(actorHash).substring(0, 8) + "..." : "system");
            }
        } catch (Exception e) {
            log.error("Audit event [{}] failed: {}", eventType, e.getMessage());
        }
    }

    private Map<String, String> sanitize(Map<String, Object> metadata) {
        if (metadata == null) return Map.of();
        return metadata.entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        e -> PII_KEYS.contains(e.getKey().toLowerCase())
                                ? "[REDACTED]"
                                : String.valueOf(e.getValue())
                ));
    }
}
