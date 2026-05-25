package gov.census.platform.common.util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;

/**
 * Cryptographic hashing utilities.
 * All methods are deterministic and constant-time where security-sensitive.
 */
public final class HashUtil {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of();

    private HashUtil() {}

    /**
     * SHA3-256 hash of (salt + input). Deterministic.
     * Used for: phone hashing, face embedding hashing, document hashing.
     */
    public static byte[] sha3Hash(String salt, String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA3-256");
            md.update(salt.getBytes(StandardCharsets.UTF_8));
            return md.digest(input.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA3-256 not available", e);
        }
    }

    public static byte[] sha3Hash(byte[] salt, byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA3-256");
            md.update(salt);
            return md.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA3-256 not available", e);
        }
    }

    /**
     * HMAC-SHA256 for audit event signing.
     */
    public static byte[] hmacSha256(String secret, String content) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(
                    secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"
            ));
            return mac.doFinal(content.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA256 failed", e);
        }
    }

    /**
     * Nullifier: unique per (citizenIdHash, censusId).
     * Prevents double-submission across census periods.
     */
    public static byte[] computeNullifier(byte[] citizenIdHash, String censusId) {
        return sha3Hash(citizenIdHash, censusId.getBytes(StandardCharsets.UTF_8));
    }

    public static String toHex(byte[] bytes) {
        return HEX.formatHex(bytes);
    }

    public static byte[] fromHex(String hex) {
        return HEX.parseHex(hex);
    }

    public static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

    /** Derive per-citizen salt from master key + citizenId. */
    public static byte[] deriveCitizenSalt(String masterKey, String citizenId) {
        return sha3Hash(masterKey, citizenId);
    }
}
