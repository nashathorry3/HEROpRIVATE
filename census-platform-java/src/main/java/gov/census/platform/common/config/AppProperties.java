package gov.census.platform.common.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Data
@Validated
@ConfigurationProperties(prefix = "census")
public class AppProperties {

    private Security security = new Security();
    private Face face = new Face();
    private Fraud fraud = new Fraud();
    private Census census = new Census();
    private Twilio twilio = new Twilio();

    @Data
    public static class Security {
        private Jwt jwt = new Jwt();
        private Otp otp = new Otp();
        private Crypto crypto = new Crypto();

        @Data
        public static class Jwt {
            @NotBlank
            private String secret;
            @Positive
            private int sessionTtlMinutes = 10;
        }

        @Data
        public static class Otp {
            @Positive
            private int ttlSeconds = 300;
            @Positive
            private int maxAttempts = 3;
            @Positive
            private int rateLimitWindowSeconds = 600;
            @Positive
            private int rateLimitMaxRequests = 5;
        }

        @Data
        public static class Crypto {
            @NotBlank
            private String globalPhoneSalt;
            @NotBlank
            private String encryptionKey;
            @NotBlank
            private String hmacSecret;
        }
    }

    @Data
    public static class Face {
        private double similarityThreshold = 0.85;
        private double livenessThreshold = 0.92;
        private String modelServiceUrl;
    }

    @Data
    public static class Fraud {
        private double blockThreshold = 0.85;
        private double reviewThreshold = 0.70;
    }

    @Data
    public static class Census {
        @NotBlank
        private String id = "CENSUS-2026";
        @Positive
        private int kAnonymityThreshold = 100;
    }

    @Data
    public static class Twilio {
        @NotBlank
        private String accountSid;
        @NotBlank
        private String authToken;
        @NotBlank
        private String fromNumber;
    }
}
