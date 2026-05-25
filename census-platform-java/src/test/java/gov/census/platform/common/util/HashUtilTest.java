package gov.census.platform.common.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("HashUtil")
class HashUtilTest {

    @Test
    @DisplayName("sha3Hash is deterministic — same inputs always produce same output")
    void sha3HashIsDeterministic() {
        byte[] h1 = HashUtil.sha3Hash("salt", "phone:+9647001234567");
        byte[] h2 = HashUtil.sha3Hash("salt", "phone:+9647001234567");
        assertThat(h1).isEqualTo(h2);
    }

    @Test
    @DisplayName("sha3Hash produces different output for different salts")
    void sha3HashDiffersBySlat() {
        byte[] h1 = HashUtil.sha3Hash("salt1", "input");
        byte[] h2 = HashUtil.sha3Hash("salt2", "input");
        assertThat(h1).isNotEqualTo(h2);
    }

    @Test
    @DisplayName("sha3Hash is 32 bytes (SHA3-256 output)")
    void sha3HashIs32Bytes() {
        byte[] hash = HashUtil.sha3Hash("salt", "any input");
        assertThat(hash).hasSize(32);
    }

    @Test
    @DisplayName("nullifier differs for same citizen across different census IDs")
    void nullifierDiffersByCensus() {
        byte[] citizenHash = HashUtil.sha3Hash("", "citizen-123");
        byte[] n1 = HashUtil.computeNullifier(citizenHash, "CENSUS-2026");
        byte[] n2 = HashUtil.computeNullifier(citizenHash, "CENSUS-2031");
        assertThat(n1).isNotEqualTo(n2);
    }

    @Test
    @DisplayName("nullifier is same for same citizen + census (deterministic)")
    void nullifierIsDeterministic() {
        byte[] citizenHash = HashUtil.sha3Hash("", "citizen-123");
        byte[] n1 = HashUtil.computeNullifier(citizenHash, "CENSUS-2026");
        byte[] n2 = HashUtil.computeNullifier(citizenHash, "CENSUS-2026");
        assertThat(n1).isEqualTo(n2);
    }

    @Test
    @DisplayName("toHex and fromHex are inverse operations")
    void hexRoundTrip() {
        byte[] original = HashUtil.randomBytes(32);
        assertThat(HashUtil.fromHex(HashUtil.toHex(original))).isEqualTo(original);
    }

    @Test
    @DisplayName("HMAC is deterministic for same key and content")
    void hmacIsDeterministic() {
        byte[] m1 = HashUtil.hmacSha256("secret-key", "content");
        byte[] m2 = HashUtil.hmacSha256("secret-key", "content");
        assertThat(m1).isEqualTo(m2);
    }

    @Test
    @DisplayName("HMAC differs for different keys")
    void hmacDiffersByKey() {
        byte[] m1 = HashUtil.hmacSha256("key1", "content");
        byte[] m2 = HashUtil.hmacSha256("key2", "content");
        assertThat(m1).isNotEqualTo(m2);
    }
}
