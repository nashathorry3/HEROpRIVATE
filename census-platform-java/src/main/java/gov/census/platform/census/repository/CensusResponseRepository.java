package gov.census.platform.census.repository;

import gov.census.platform.census.model.CensusResponse;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.UUID;

@Repository
public interface CensusResponseRepository extends JpaRepository<CensusResponse, UUID> {

    boolean existsByTokenNullifier(byte[] tokenNullifier);

    long countByRegionCode(String regionCode);

    /**
     * k-Anonymity enforced: groups smaller than threshold are excluded.
     * This query is used for aggregate statistics only.
     */
    @Query(value = """
        SELECT
            ethnicity_code,
            COUNT(*) as count,
            ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER(), 2) as percentage
        FROM census.census_responses
        WHERE region_code = :regionCode
        GROUP BY ethnicity_code
        HAVING COUNT(*) >= :kThreshold
        ORDER BY count DESC
        """, nativeQuery = true)
    java.util.List<Map<String, Object>> getEthnicityStats(String regionCode, int kThreshold);

    @Query(value = """
        SELECT
            religion_code,
            COUNT(*) as count
        FROM census.census_responses
        WHERE region_code = :regionCode
        GROUP BY religion_code
        HAVING COUNT(*) >= :kThreshold
        ORDER BY count DESC
        """, nativeQuery = true)
    java.util.List<Map<String, Object>> getReligionStats(String regionCode, int kThreshold);
}
