package io.github.marcofanti.aauth.personserver.persistence;

import io.github.marcofanti.aauth.personserver.ps.MissionUtils;
import io.github.marcofanti.aauth.personserver.ps.RevocationStore;
import java.util.List;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;

/** SQL-backed {@link RevocationStore} ({@code ps_revocation}, {@code ps_agent_token}). */
public final class SqlRevocationStore implements RevocationStore {

    private final JdbcTemplate jdbc;

    public SqlRevocationStore(DataSource dataSource) {
        this.jdbc = new JdbcTemplate(dataSource);
    }

    @Override
    public synchronized void revoke(String iss, String jti, long exp) {
        if (!isRevoked(iss, jti)) {
            jdbc.update(
                    "INSERT INTO ps_revocation (iss, jti, exp) VALUES (?, ?, ?)",
                    MissionUtils.stripTrailingSlash(iss),
                    jti,
                    exp);
        }
    }

    @Override
    public boolean isRevoked(String iss, String jti) {
        if (iss == null || jti == null) {
            return false;
        }
        Integer count = jdbc.queryForObject(
                "SELECT COUNT(*) FROM ps_revocation WHERE iss = ? AND jti = ?",
                Integer.class,
                MissionUtils.stripTrailingSlash(iss),
                jti);
        return count != null && count > 0;
    }

    @Override
    public synchronized void recordAgentToken(String iss, String jti, String sub, long exp) {
        if (agentSub(iss, jti) == null) {
            jdbc.update(
                    "INSERT INTO ps_agent_token (iss, jti, sub, exp) VALUES (?, ?, ?, ?)",
                    MissionUtils.stripTrailingSlash(iss),
                    jti,
                    sub,
                    exp);
        }
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
    public synchronized void recordAgentRevocation(String agentSub, long epochSeconds) {
        Long previous = agentRevokedAt(agentSub);
        if (previous == null) {
            jdbc.update("INSERT INTO ps_agent_revocation (sub, revoked_at) VALUES (?, ?)", agentSub, epochSeconds);
        } else if (epochSeconds > previous) {
            jdbc.update("UPDATE ps_agent_revocation SET revoked_at = ? WHERE sub = ?", epochSeconds, agentSub);
        }
    }

    @Override
    public Long agentRevokedAt(String agentSub) {
        List<Long> rows =
                jdbc.queryForList("SELECT revoked_at FROM ps_agent_revocation WHERE sub = ?", Long.class, agentSub);
        return rows.isEmpty() ? null : rows.getFirst();
    }
}
