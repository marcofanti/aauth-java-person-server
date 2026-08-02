package io.github.marcofanti.aauth.personserver.persistence;

import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.personserver.agentserver.BindingNotFoundException;
import io.github.marcofanti.aauth.personserver.agentserver.BindingStore;
import io.github.marcofanti.aauth.personserver.agentserver.DuplicateStableKeyException;
import io.github.marcofanti.aauth.personserver.agentserver.MemoryPendingRegistrationStore;
import io.github.marcofanti.aauth.personserver.agentserver.PendingRegistrationStore;
import io.github.marcofanti.aauth.personserver.agentserver.RegistrationNotFoundException;
import io.github.marcofanti.aauth.personserver.model.Binding;
import io.github.marcofanti.aauth.personserver.model.PendingRegistration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;

/** SQL-backed Agent Server stores ({@code as_pending_registration}, {@code as_binding[_jkt]}). */
public final class SqlAgentServerStores {

    private SqlAgentServerStores() {}

    /** SQL {@link PendingRegistrationStore}. */
    public static final class Registrations implements PendingRegistrationStore {

        private final JdbcTemplate jdbc;
        private final int defaultTtlSeconds;

        public Registrations(DataSource dataSource, int defaultTtlSeconds) {
            this.jdbc = new JdbcTemplate(dataSource);
            this.defaultTtlSeconds = defaultTtlSeconds;
        }

        private static PendingRegistration mapRow(java.sql.ResultSet rs) throws java.sql.SQLException {
            return new PendingRegistration(
                    rs.getString("id"),
                    Json.readMap(rs.getString("stable_pub_json")),
                    Json.readMap(rs.getString("ephemeral_pub_json")),
                    rs.getString("agent_name"),
                    rs.getString("stable_jkt"),
                    Instant.parse(rs.getString("created_at")),
                    Instant.parse(rs.getString("expires_at")),
                    rs.getString("status"));
        }

        private void setStatus(String pendingId, String status) {
            jdbc.update("UPDATE as_pending_registration SET status = ? WHERE id = ?", status, pendingId);
        }

        @Override
        public PendingRegistration create(
                java.util.Map<String, Object> stablePub,
                java.util.Map<String, Object> ephemeralPub,
                String agentName,
                String stableJkt) {
            Instant now = Instant.now();
            PendingRegistration registration = new PendingRegistration(
                    MemoryPendingRegistrationStore.newId(),
                    stablePub,
                    ephemeralPub,
                    agentName,
                    stableJkt,
                    now,
                    now.plusSeconds(defaultTtlSeconds),
                    "pending");
            jdbc.update(
                    "INSERT INTO as_pending_registration (id, stable_pub_json, ephemeral_pub_json, agent_name, "
                            + "stable_jkt, created_at, expires_at, status) VALUES (?,?,?,?,?,?,?,?)",
                    registration.id(),
                    PendingSerde.write(registration.stablePub()),
                    PendingSerde.write(registration.ephemeralPub()),
                    registration.agentName(),
                    registration.stableJkt(),
                    registration.createdAt().toString(),
                    registration.expiresAt().toString(),
                    registration.status());
            return registration;
        }

        @Override
        public PendingRegistration get(String pendingId) {
            List<PendingRegistration> rows = jdbc.query(
                    "SELECT * FROM as_pending_registration WHERE id = ?", (rs, rowNum) -> mapRow(rs), pendingId);
            if (rows.isEmpty()) {
                return null;
            }
            PendingRegistration registration = rows.getFirst();
            if ("pending".equals(registration.status()) && !Instant.now().isBefore(registration.expiresAt())) {
                registration = registration.withStatus("denied");
                setStatus(pendingId, "denied");
            }
            return registration;
        }

        @Override
        public void approve(String pendingId) {
            if (get(pendingId) == null) {
                throw new RegistrationNotFoundException();
            }
            setStatus(pendingId, "approved");
        }

        @Override
        public void deny(String pendingId) {
            if (get(pendingId) == null) {
                throw new RegistrationNotFoundException();
            }
            setStatus(pendingId, "denied");
        }

        @Override
        public List<PendingRegistration> listPending() {
            List<PendingRegistration> rows = jdbc.query(
                    "SELECT * FROM as_pending_registration WHERE status = 'pending' ORDER BY created_at",
                    (rs, rowNum) -> mapRow(rs));
            Instant now = Instant.now();
            List<PendingRegistration> out = new ArrayList<>();
            for (PendingRegistration registration : rows) {
                if (!now.isBefore(registration.expiresAt())) {
                    setStatus(registration.id(), "denied");
                    continue;
                }
                out.add(registration);
            }
            return out;
        }

        @Override
        public PendingRegistration findByStableJkt(String stableJkt) {
            Instant now = Instant.now();
            List<PendingRegistration> rows = jdbc.query(
                    "SELECT * FROM as_pending_registration WHERE stable_jkt = ? AND status = 'pending'",
                    (rs, rowNum) -> mapRow(rs),
                    stableJkt);
            for (PendingRegistration registration : rows) {
                if (now.isBefore(registration.expiresAt())) {
                    return registration;
                }
            }
            return null;
        }
    }

    /** SQL {@link BindingStore}. */
    public static final class Bindings implements BindingStore {

        private final JdbcTemplate jdbc;

        public Bindings(DataSource dataSource) {
            this.jdbc = new JdbcTemplate(dataSource);
        }

        private record BindingRow(String agentId, String agentName, String createdAt, boolean revoked) {}

        /** Thumbprints are fetched after the outer query completes — with SQLite's single
         * connection, a nested query inside a row mapper would deadlock the pool. */
        private Binding toBinding(BindingRow row) {
            List<String> thumbprints = jdbc.query(
                    "SELECT jkt FROM as_binding_jkt WHERE agent_id = ? ORDER BY position",
                    (rs, rowNum) -> rs.getString("jkt"),
                    row.agentId());
            return new Binding(
                    row.agentId(), row.agentName(), Instant.parse(row.createdAt()), thumbprints, row.revoked());
        }

        @Override
        public Binding create(String agentId, String agentName, String stableJkt) {
            Instant now = Instant.now();
            jdbc.update(
                    "INSERT INTO as_binding (agent_id, agent_name, created_at, revoked) VALUES (?,?,?,?)",
                    agentId,
                    agentName,
                    now.toString(),
                    false);
            jdbc.update("INSERT INTO as_binding_jkt (jkt, agent_id, position) VALUES (?,?,0)", stableJkt, agentId);
            return new Binding(agentId, agentName, now, List.of(stableJkt), false);
        }

        @Override
        public Binding lookupByStableJkt(String jkt) {
            List<String> agentIds = jdbc.query(
                    "SELECT agent_id FROM as_binding_jkt WHERE jkt = ?", (rs, rowNum) -> rs.getString("agent_id"), jkt);
            return agentIds.isEmpty() ? null : getByAgentId(agentIds.getFirst());
        }

        @Override
        public Binding getByAgentId(String agentId) {
            List<BindingRow> rows = jdbc.query(
                    "SELECT * FROM as_binding WHERE agent_id = ?",
                    (rs, rowNum) -> new BindingRow(
                            rs.getString("agent_id"),
                            rs.getString("agent_name"),
                            rs.getString("created_at"),
                            rs.getBoolean("revoked")),
                    agentId);
            return rows.isEmpty() ? null : toBinding(rows.getFirst());
        }

        @Override
        public void updateAgentName(String agentId, String agentName) {
            int updated =
                    jdbc.update("UPDATE as_binding SET agent_name = ? WHERE agent_id = ?", agentName.strip(), agentId);
            if (updated == 0) {
                throw new BindingNotFoundException();
            }
        }

        @Override
        public List<Binding> listAll() {
            List<BindingRow> rows = jdbc.query(
                    "SELECT * FROM as_binding ORDER BY created_at",
                    (rs, rowNum) -> new BindingRow(
                            rs.getString("agent_id"),
                            rs.getString("agent_name"),
                            rs.getString("created_at"),
                            rs.getBoolean("revoked")));
            List<Binding> out = new ArrayList<>();
            for (BindingRow row : rows) {
                out.add(toBinding(row));
            }
            return out;
        }

        @Override
        public void addStableKey(String agentId, String stableJkt) {
            Binding binding = getByAgentId(agentId);
            if (binding == null) {
                throw new BindingNotFoundException();
            }
            if (binding.stableKeyThumbprints().contains(stableJkt)) {
                throw new DuplicateStableKeyException();
            }
            jdbc.update(
                    "INSERT INTO as_binding_jkt (jkt, agent_id, position) VALUES (?,?,?)",
                    stableJkt,
                    agentId,
                    binding.stableKeyThumbprints().size());
        }

        @Override
        public void revoke(String agentId) {
            int updated = jdbc.update("UPDATE as_binding SET revoked = TRUE WHERE agent_id = ?", agentId);
            if (updated == 0) {
                throw new BindingNotFoundException();
            }
        }
    }
}
