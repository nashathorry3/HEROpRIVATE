package gov.census.platform.common.security;

import gov.census.platform.common.config.AppProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Short-lived JWT session tokens.
 * Not stored in DB — stateless, verified cryptographically.
 * Contains: citizenId (anonymous UUID), roles, verificationLevel.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class JwtService {

    private final AppProperties props;

    private SecretKey getSigningKey() {
        byte[] keyBytes = props.getSecurity().getJwt().getSecret()
                .getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String issueSessionToken(String citizenId, int verificationLevel, List<String> roles) {
        Instant now = Instant.now();
        int ttl = props.getSecurity().getJwt().getSessionTtlMinutes();

        return Jwts.builder()
                .subject(citizenId)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(ttl, ChronoUnit.MINUTES)))
                .claims(Map.of(
                        "roles", roles,
                        "verificationLevel", verificationLevel,
                        "iss", "census-platform"
                ))
                .signWith(getSigningKey())
                .compact();
    }

    public Optional<Claims> validateToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return Optional.of(claims);
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            return Optional.empty();
        }
    }

    public Optional<String> extractCitizenId(String token) {
        return validateToken(token).map(Claims::getSubject);
    }
}
