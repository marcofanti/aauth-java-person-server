package io.github.marcofanti.aauth.personserver.persistence;

import io.github.marcofanti.aauth.personserver.ps.MissionUtils;
import io.github.marcofanti.aauth.personserver.ps.PersonTokenLedger;
import java.util.List;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;

/** SQL-backed {@link PersonTokenLedger} ({@code ps_resource_approval}, {@code ps_person_token}). */
public final class SqlPersonTokenLedger implements PersonTokenLedger {

    private final JdbcTemplate jdbc;

    public SqlPersonTokenLedger(DataSource dataSource) {
        this.jdbc = new JdbcTemplate(dataSource);
    }

    @Override
    public boolean isApproved(String person, String resource) {
        Integer count = jdbc.queryForObject(
                "SELECT COUNT(*) FROM ps_resource_approval WHERE person = ? AND resource = ?",
                Integer.class,
                person,
                MissionUtils.stripTrailingSlash(resource));
        return count != null && count > 0;
    }

    @Override
    public synchronized void approve(String person, String resource) {
        if (!isApproved(person, resource)) {
            jdbc.update(
                    "INSERT INTO ps_resource_approval (person, resource) VALUES (?, ?)",
                    person,
                    MissionUtils.stripTrailingSlash(resource));
        }
    }

    @Override
    public void recordIssued(Issued issued) {
        jdbc.update(
                "INSERT INTO ps_person_token (jti, agent_id, person, aud, sub, exp) VALUES (?,?,?,?,?,?)",
                issued.jti(),
                issued.agentId(),
                issued.person(),
                issued.aud(),
                issued.sub(),
                issued.exp());
    }

    @Override
    public Issued findByJti(String jti) {
        List<Issued> rows = jdbc.query(
                "SELECT * FROM ps_person_token WHERE jti = ?",
                (rs, rowNum) -> new Issued(
                        rs.getString("jti"),
                        rs.getString("agent_id"),
                        rs.getString("person"),
                        rs.getString("aud"),
                        rs.getString("sub"),
                        rs.getLong("exp")),
                jti);
        return rows.isEmpty() ? null : rows.getFirst();
    }

    @Override
    public int distinctLiveResources(String agentId, String exclude, long nowEpochSeconds) {
        Integer count = jdbc.queryForObject(
                "SELECT COUNT(DISTINCT aud) FROM ps_person_token WHERE agent_id = ? AND exp > ? AND aud <> ?",
                Integer.class,
                agentId,
                nowEpochSeconds,
                MissionUtils.stripTrailingSlash(exclude));
        return count == null ? 0 : count;
    }
}
