package io.github.marcofanti.aauth.personserver.persistence;

import io.github.marcofanti.aauth.personserver.ps.AgentServerTrustRegistry;
import io.github.marcofanti.aauth.personserver.ps.IssuerUrls;
import io.github.marcofanti.aauth.personserver.ps.MemoryAgentServerTrustRegistry;
import io.github.marcofanti.aauth.personserver.ps.TrustedAgentServer;
import java.util.List;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;

/** SQL-backed trust registry ({@code ps_trusted_agent_server}). */
public final class SqlTrustRegistry implements AgentServerTrustRegistry {

    private final JdbcTemplate jdbc;

    public SqlTrustRegistry(DataSource dataSource) {
        this.jdbc = new JdbcTemplate(dataSource);
    }

    /** One-time JSON trust file import when the table is empty (DATABASE.md). */
    public void importFromFileIfEmpty(String trustFile) {
        if (trustFile == null || trustFile.isEmpty()) {
            return;
        }
        Integer count = jdbc.queryForObject("SELECT COUNT(*) FROM ps_trusted_agent_server", Integer.class);
        if (count != null && count > 0) {
            return;
        }
        for (TrustedAgentServer entry : new MemoryAgentServerTrustRegistry(trustFile).listTrusted()) {
            add(entry);
        }
    }

    @Override
    public List<TrustedAgentServer> listTrusted() {
        return jdbc.query(
                "SELECT * FROM ps_trusted_agent_server ORDER BY issuer",
                (rs, rowNum) -> new TrustedAgentServer(
                        rs.getString("issuer"),
                        rs.getString("display_name"),
                        rs.getString("jwks_uri"),
                        rs.getString("jwks_fingerprint"),
                        rs.getString("added_at")));
    }

    @Override
    public void add(TrustedAgentServer entry) {
        String issuer = IssuerUrls.normalizeIssuer(entry.issuer());
        jdbc.update("DELETE FROM ps_trusted_agent_server WHERE issuer = ?", issuer);
        jdbc.update(
                "INSERT INTO ps_trusted_agent_server (issuer, display_name, jwks_uri, jwks_fingerprint, added_at) "
                        + "VALUES (?,?,?,?,?)",
                issuer,
                entry.displayName(),
                entry.jwksUri(),
                entry.jwksFingerprint(),
                entry.addedAt());
    }

    @Override
    public boolean remove(String issuer) {
        return jdbc.update("DELETE FROM ps_trusted_agent_server WHERE issuer = ?", IssuerUrls.normalizeIssuer(issuer))
                > 0;
    }

    @Override
    public boolean isTrusted(String issuer) {
        Integer count = jdbc.queryForObject(
                "SELECT COUNT(*) FROM ps_trusted_agent_server WHERE issuer = ?",
                Integer.class,
                IssuerUrls.normalizeIssuer(issuer));
        return count != null && count > 0;
    }
}
