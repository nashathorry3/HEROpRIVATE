package gov.census.platform.common.config;

import gov.census.platform.audit.model.AuditLog;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.kafka.core.KafkaTemplate;

import java.util.concurrent.TimeUnit;

/**
 * Dev-only configuration.
 * Provides in-process stubs for infrastructure services
 * (Redis, Kafka) so the app can start without external dependencies.
 */
@Slf4j
@Configuration
@Profile("dev")
public class DevConfiguration {

    /**
     * Fake StringRedisTemplate backed by ConcurrentHashMap.
     * Rate limiting and OTP sessions still work in-memory.
     */
    @Bean
    @ConditionalOnMissingBean(StringRedisTemplate.class)
    public StringRedisTemplate devStringRedisTemplate() {
        log.warn("DEV MODE: Using in-memory Redis stub — not suitable for production");
        try {
            // Try to connect to real Redis if available
            LettuceConnectionFactory factory = new LettuceConnectionFactory(
                    new RedisStandaloneConfiguration("localhost", 6379)
            );
            factory.afterPropertiesSet();
            return new StringRedisTemplate(factory);
        } catch (Exception e) {
            // Fall back to no-op stub
            return new NoOpStringRedisTemplate();
        }
    }

    /**
     * No-op Kafka template — audit events are logged instead.
     */
    @Bean
    @ConditionalOnMissingBean
    public KafkaTemplate<String, AuditLog> devKafkaTemplate() {
        log.warn("DEV MODE: Kafka unavailable — audit events go to log only");
        return null;  // AuditService handles null gracefully
    }

    // ─── Inner no-op Redis stub ───────────────────────────────────────────────

    static class NoOpStringRedisTemplate extends StringRedisTemplate {

        private final java.util.concurrent.ConcurrentHashMap<String, String> store =
                new java.util.concurrent.ConcurrentHashMap<>();
        private final java.util.concurrent.ConcurrentHashMap<String, Long> expiry =
                new java.util.concurrent.ConcurrentHashMap<>();

        NoOpStringRedisTemplate() {}

        @Override
        public org.springframework.data.redis.core.ValueOperations<String, String> opsForValue() {
            return new NoOpValueOps(store, expiry);
        }

        @Override
        public Boolean expire(String key, long timeout,
                              java.util.concurrent.TimeUnit unit) {
            long expireAt = System.currentTimeMillis() + unit.toMillis(timeout);
            expiry.put(key, expireAt);
            return true;
        }

        @Override
        public Boolean hasKey(String key) {
            Long exp = expiry.get(key);
            if (exp != null && System.currentTimeMillis() > exp) {
                store.remove(key);
                expiry.remove(key);
                return false;
            }
            return store.containsKey(key);
        }

        @Override
        public Boolean delete(String key) {
            store.remove(key);
            expiry.remove(key);
            return true;
        }
    }

    static class NoOpValueOps implements
            org.springframework.data.redis.core.ValueOperations<String, String> {

        private final java.util.concurrent.ConcurrentHashMap<String, String> store;
        private final java.util.concurrent.ConcurrentHashMap<String, Long> expiry;

        NoOpValueOps(java.util.concurrent.ConcurrentHashMap<String, String> store,
                     java.util.concurrent.ConcurrentHashMap<String, Long> expiry) {
            this.store = store;
            this.expiry = expiry;
        }

        @Override
        public Long increment(String key) {
            String val = store.merge(key, "1",
                    (old, one) -> String.valueOf(Long.parseLong(old) + 1));
            return Long.parseLong(val);
        }

        @Override
        public Long increment(String key, long delta) {
            String val = store.merge(key, String.valueOf(delta),
                    (old, d) -> String.valueOf(Long.parseLong(old) + delta));
            return Long.parseLong(val);
        }

        @Override
        public void set(String key, String value) { store.put(key, value); }

        @Override
        public void set(String key, String value, long timeout, TimeUnit unit) {
            store.put(key, value);
            expiry.put(key, System.currentTimeMillis() + unit.toMillis(timeout));
        }

        @Override
        public String get(Object key) {
            String k = (String) key;
            Long exp = expiry.get(k);
            if (exp != null && System.currentTimeMillis() > exp) {
                store.remove(k);
                expiry.remove(k);
                return null;
            }
            return store.get(k);
        }

        // ─── Unused interface methods ─────────────────────────────────────────
        @Override public void set(String key, String value, java.time.Duration timeout) { set(key, value); }
        @Override public Boolean setIfAbsent(String key, String value) { return store.putIfAbsent(key, value) == null; }
        @Override public Boolean setIfAbsent(String key, String value, long timeout, TimeUnit unit) { return store.putIfAbsent(key, value) == null; }
        @Override public Boolean setIfAbsent(String key, String value, java.time.Duration timeout) { return store.putIfAbsent(key, value) == null; }
        @Override public Boolean setIfPresent(String key, String value) { return false; }
        @Override public Boolean setIfPresent(String key, String value, long timeout, TimeUnit unit) { return false; }
        @Override public Boolean setIfPresent(String key, String value, java.time.Duration timeout) { return false; }
        @Override public void multiSet(java.util.Map<? extends String, ? extends String> map) {}
        @Override public Boolean multiSetIfAbsent(java.util.Map<? extends String, ? extends String> map) { return false; }
        @Override public String getAndDelete(String key) { return store.remove(key); }
        @Override public String getAndExpire(String key, long timeout, TimeUnit unit) { return get(key); }
        @Override public String getAndExpire(String key, java.time.Duration timeout) { return get(key); }
        @Override public String getAndPersist(String key) { return get(key); }
        @Override public String getAndSet(String key, String value) { return store.put(key, value); }
        @Override public java.util.List<String> multiGet(java.util.Collection<String> keys) { return java.util.Collections.emptyList(); }
        @Override public Double increment(String key, double delta) { String val = store.merge(key, String.valueOf(delta), (old, d) -> String.valueOf(Double.parseDouble(old) + delta)); return Double.parseDouble(val); }
        @Override public Long decrement(String key) { return increment(key, -1); }
        @Override public Long decrement(String key, long delta) { return increment(key, -delta); }
        @Override public Integer append(String key, String value) { store.merge(key, value, String::concat); return store.get(key).length(); }
        @Override public String get(String key, long start, long end) { return get(key); }
        @Override public void set(String key, String value, long offset) { set(key, value); }
        @Override public Long size(String key) { String v = get(key); return v == null ? 0L : (long) v.length(); }
        @Override public Boolean setBit(String key, long offset, boolean value) { return false; }
        @Override public Boolean getBit(String key, long offset) { return false; }
        @Override public java.util.List<Long> bitField(String key, org.springframework.data.redis.connection.BitFieldSubCommands subCommands) { return java.util.Collections.emptyList(); }
        @Override public org.springframework.data.redis.core.RedisOperations<String, String> getOperations() { return null; }
    }
}
