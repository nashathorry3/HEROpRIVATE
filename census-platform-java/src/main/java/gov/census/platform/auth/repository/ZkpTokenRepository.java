package gov.census.platform.auth.repository;

import gov.census.platform.auth.model.ZkpToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface ZkpTokenRepository extends JpaRepository<ZkpToken, UUID> {

    Optional<ZkpToken> findByNullifierHash(byte[] nullifierHash);

    boolean existsByNullifierHash(byte[] nullifierHash);
}
