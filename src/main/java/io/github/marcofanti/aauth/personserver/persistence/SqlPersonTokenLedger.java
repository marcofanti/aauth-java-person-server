package io.github.marcofanti.aauth.personserver.persistence;

import io.github.marcofanti.aauth.personserver.ps.ExpiredRecords;
import io.github.marcofanti.aauth.personserver.ps.MissionUtils;
import io.github.marcofanti.aauth.personserver.ps.PersonTokenLedger;
import java.util.List;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;

/** SQL-backed {@link PersonTokenLedger} ({@code ps_resource_approval}, {@code ps_person_token}). */
public final class SqlPersonTokenLedger implements PersonTokenLedger {

    private final JdbcTemplate jdbc;
    private final ExpiredRecords expired = new ExpiredRecords();

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
        long cutoff = expired.cutoffIfDue();
        if (cutoff >= 0) {
            purgeExpired(cutoff);
        }
    }

    @Override
    public Issued findByJti(String jti) {
        List<Issued> rows =
                jdbc.query("SELECT * FROM ps_person_token WHERE jti = ?", SqlPersonTokenLedger::issued, jti);
        return rows.isEmpty() ? null : rows.getFirst();
    }

    @Override
    public void recordPresentation(String jti, String asIssuer, String agentJkt) {
        jdbc.update(
                "INSERT INTO ps_person_token_presentation (jti, as_iss, agent_jkt) VALUES (?, ?, ?) "
                        + "ON CONFLICT DO NOTHING",
                jti,
                MissionUtils.stripTrailingSlash(asIssuer),
                agentJkt);
    }

    @Override
    public List<Presentation> presentations(String jti) {
        return jdbc.query(
                "SELECT as_iss, agent_jkt FROM ps_person_token_presentation WHERE jti = ? ORDER BY as_iss",
                (rs, rowNum) -> new Presentation(rs.getString("as_iss"), rs.getString("agent_jkt")),
                jti);
    }

    @Override
    public void recordUpstream(String jti, String upstreamIss, String upstreamJti) {
        jdbc.update(
                "INSERT INTO ps_person_token_upstream (jti, upstream_iss, upstream_jti) VALUES (?, ?, ?) "
                        + "ON CONFLICT DO NOTHING",
                jti,
                MissionUtils.stripTrailingSlash(upstreamIss),
                upstreamJti);
    }

    @Override
    public List<Issued> issuedFromUpstream(String upstreamIss, String upstreamJti) {
        return jdbc.query(
                "SELECT t.* FROM ps_person_token t JOIN ps_person_token_upstream u ON u.jti = t.jti "
                        + "WHERE u.upstream_iss = ? AND u.upstream_jti = ?",
                SqlPersonTokenLedger::issued,
                MissionUtils.stripTrailingSlash(upstreamIss),
                upstreamJti);
    }

    @Override
    public List<Issued> findBySubject(String aud, String sub) {
        return jdbc.query(
                "SELECT * FROM ps_person_token WHERE aud = ? AND sub = ?",
                SqlPersonTokenLedger::issued,
                MissionUtils.stripTrailingSlash(aud),
                sub);
    }

    @Override
    public List<Issued> liveFor(String agentId, long nowEpochSeconds) {
        return jdbc.query(
                "SELECT * FROM ps_person_token WHERE agent_id = ? AND exp > ?",
                SqlPersonTokenLedger::issued,
                agentId,
                nowEpochSeconds);
    }

    private static Issued issued(java.sql.ResultSet rs, int rowNum) throws java.sql.SQLException {
        return new Issued(
                rs.getString("jti"),
                rs.getString("agent_id"),
                rs.getString("person"),
                rs.getString("aud"),
                rs.getString("sub"),
                rs.getLong("exp"));
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

    @Override
    public void purgeExpired(long cutoffEpochSeconds) {
        String expiredJtis = "SELECT jti FROM ps_person_token WHERE exp <= ?";
        jdbc.update("DELETE FROM ps_person_token_presentation WHERE jti IN (" + expiredJtis + ")", cutoffEpochSeconds);
        jdbc.update("DELETE FROM ps_person_token_upstream WHERE jti IN (" + expiredJtis + ")", cutoffEpochSeconds);
        jdbc.update("DELETE FROM ps_person_token WHERE exp <= ?", cutoffEpochSeconds);
    }
}
