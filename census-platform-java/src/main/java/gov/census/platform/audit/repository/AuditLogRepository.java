package gov.census.platform.audit.repository;

import gov.census.platform.audit.model.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    List<AuditLog> findByEventTypeAndEventTimeBetween(
            String eventType, Instant from, Instant to
    );

    @Query("SELECT a FROM AuditLog a WHERE a.outcome = 'blocked' " +
           "AND a.eventTime > :since ORDER BY a.eventTime DESC")
    List<AuditLog> findRecentBlocked(Instant since);

    long countByEventTypeAndOutcome(String eventType, String outcome);
}
