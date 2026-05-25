package gov.census.platform.auth.repository;

import gov.census.platform.auth.model.OtpSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface OtpSessionRepository extends JpaRepository<OtpSession, UUID> {

    Optional<OtpSession> findByPhoneHash(byte[] phoneHash);

    void deleteByPhoneHash(byte[] phoneHash);

    @Modifying
    @Query("DELETE FROM OtpSession o WHERE o.expiresAt < :now")
    int deleteExpiredSessions(Instant now);
}
