package io.github.marcofanti.aauth.personserver.persistence;

import io.github.marcofanti.aauth.personserver.ps.ExpiredRecords;
import io.github.marcofanti.aauth.personserver.ps.MissionUtils;
import io.github.marcofanti.aauth.personserver.ps.RevocationStore;
import java.util.List;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * SQL-backed {@link RevocationStore}. Writes are {@code INSERT … ON CONFLICT DO NOTHING}
 * (SQLite and PostgreSQL), so concurrent or repeated records are no-ops across instances.
 */
public final class SqlRevocationStore implements RevocationStore {

    private final JdbcTemplate jdbc;
    private final ExpiredRecords expired = new ExpiredRecords();

    public SqlRevocationStore(DataSource dataSource) {
        this.jdbc = new JdbcTemplate(dataSource);
    }

    @Override
    public void recordResourceIssuer(String iss) {
        jdbc.update(
                "INSERT INTO ps_resource_issuer (iss) VALUES (?) ON CONFLICT DO NOTHING",
                MissionUtils.stripTrailingSlash(iss));
    }

    @Override
    public boolean isKnownResourceIssuer(String iss) {
        return !jdbc.queryForList(
                        "SELECT iss FROM ps_resource_issuer WHERE iss = ?",
                        String.class,
                        MissionUtils.stripTrailingSlash(iss))
                .isEmpty();
    }

    @Override
    public void revoke(String iss, String jti, long exp) {
        jdbc.update(
                "INSERT INTO ps_revocation (iss, jti, exp) VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
                MissionUtils.stripTrailingSlash(iss),
                jti,
                exp);
        purgeIfDue();
    }

    @Override
    public boolean isRevoked(String iss, String jti) {
        if (iss == null || jti == null) {
            return false;
        }
        return !jdbc.queryForList(
                        "SELECT jti FROM ps_revocation WHERE iss = ? AND jti = ?",
                        String.class,
                        MissionUtils.stripTrailingSlash(iss),
                        jti)
                .isEmpty();
    }

    @Override
    public void recordAgentToken(String iss, String jti, String sub, long exp) {
        jdbc.update(
                "INSERT INTO ps_agent_token (iss, jti, sub, exp) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING",
                MissionUtils.stripTrailingSlash(iss),
                jti,
                sub,
                exp);
        purgeIfDue();
    }

    @Override
    public String agentSub(String iss, String jti) {
        List<String> rows = jdbc.queryForList(
                "SELECT sub FROM ps_agent_token WHERE iss = ? AND jti = ?",
                String.class,
                MissionUtils.stripTrailingSlash(iss),
                jti);
        return rows.isEmpty() ? null : rows.getFirst();
    }

    @Override
    public void recordAgentRevocation(String agentSub, long epochSeconds) {
        jdbc.update(
                "INSERT INTO ps_agent_revocation (sub, revoked_at) VALUES (?, ?) ON CONFLICT DO NOTHING",
                agentSub,
                epochSeconds);
        jdbc.update(
                "UPDATE ps_agent_revocation SET revoked_at = ? WHERE sub = ? AND revoked_at < ?",
                epochSeconds,
                agentSub,
                epochSeconds);
    }

    @Override
    public Long agentRevokedAt(String agentSub) {
        List<Long> rows =
                jdbc.queryForList("SELECT revoked_at FROM ps_agent_revocation WHERE sub = ?", Long.class, agentSub);
        return rows.isEmpty() ? null : rows.getFirst();
    }

    @Override
    public void purgeExpired(long cutoffEpochSeconds) {
        jdbc.update("DELETE FROM ps_revocation WHERE exp <= ?", cutoffEpochSeconds);
        jdbc.update("DELETE FROM ps_agent_token WHERE exp <= ?", cutoffEpochSeconds);
    }

    private void purgeIfDue() {
        long cutoff = expired.cutoffIfDue();
        if (cutoff >= 0) {
            purgeExpired(cutoff);
        }
    }
}
