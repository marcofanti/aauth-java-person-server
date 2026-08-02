package io.github.marcofanti.aauth.personserver.persistence;

import io.github.marcofanti.aauth.personserver.ps.IssuedTokenStore;
import io.github.marcofanti.aauth.personserver.ps.MemoryIssuedTokenStore;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;

/** SQL-backed {@link IssuedTokenStore} ({@code ps_issued_token}). */
public final class SqlIssuedTokenStore implements IssuedTokenStore {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final JdbcTemplate jdbc;

    public SqlIssuedTokenStore(DataSource dataSource) {
        this.jdbc = new JdbcTemplate(dataSource);
    }

    @Override
    public void recordIssued(IssuedToken issued) {
        byte[] idBytes = new byte[16];
        RANDOM.nextBytes(idBytes);
        Object jti = MemoryIssuedTokenStore.decodeJwtPayload(issued.authToken()).get("jti");
        jdbc.update(
                "INSERT INTO ps_issued_token (issued_id, agent_id, owner_id, resource_iss, resource_scope, "
                        + "justification, issue_method, token_jti, issued_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                HexFormat.of().formatHex(idBytes),
                issued.agentId(),
                issued.ownerId(),
                issued.resourceIss(),
                issued.resourceScope(),
                issued.justification(),
                issued.issueMethod(),
                jti == null ? null : String.valueOf(jti),
                Instant.now().toString(),
                issued.expiresAt() != null ? issued.expiresAt().toString() : null);
    }

    @Override
    public List<Map<String, Object>> listIssued() {
        return jdbc.query("SELECT * FROM ps_issued_token ORDER BY issued_at DESC", (rs, rowNum) -> {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("issued_id", rs.getString("issued_id"));
            row.put("agent_id", rs.getString("agent_id"));
            row.put("owner_id", rs.getString("owner_id"));
            row.put("resource_iss", rs.getString("resource_iss"));
            row.put("resource_scope", rs.getString("resource_scope"));
            row.put("justification", rs.getString("justification"));
            row.put("issue_method", rs.getString("issue_method"));
            row.put("token_jti", rs.getString("token_jti"));
            row.put("issued_at", rs.getString("issued_at"));
            row.put("expires_at", rs.getString("expires_at"));
            return row;
        });
    }
}
