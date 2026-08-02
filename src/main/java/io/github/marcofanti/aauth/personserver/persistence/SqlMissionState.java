package io.github.marcofanti.aauth.personserver.persistence;

import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionLogEntry;
import io.github.marcofanti.aauth.personserver.model.MissionLogKind;
import io.github.marcofanti.aauth.personserver.model.MissionState;
import io.github.marcofanti.aauth.personserver.ps.MissionStatePort;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;

/** SQL-backed {@link MissionStatePort} ({@code ps_mission}, {@code ps_mission_log}). */
public final class SqlMissionState implements MissionStatePort {

    private final JdbcTemplate jdbc;

    public SqlMissionState(DataSource dataSource) {
        this.jdbc = new JdbcTemplate(dataSource);
    }

    private static Mission mapRow(java.sql.ResultSet rs) throws java.sql.SQLException {
        String approvedToolsJson = rs.getString("approved_tools_json");
        String capabilitiesJson = rs.getString("capabilities_json");
        List<java.util.Map<String, String>> approvedTools = null;
        if (approvedToolsJson != null) {
            List<Object> raw = readList(approvedToolsJson);
            List<java.util.Map<String, String>> tools = new ArrayList<>();
            for (Object item : raw) {
                if (item instanceof java.util.Map<?, ?> tool) {
                    java.util.Map<String, String> copy = new java.util.LinkedHashMap<>();
                    tool.forEach((key, value) -> copy.put(String.valueOf(key), String.valueOf(value)));
                    tools.add(copy);
                }
            }
            approvedTools = tools;
        }
        List<String> capabilities = null;
        if (capabilitiesJson != null) {
            List<String> caps = new ArrayList<>();
            for (Object item : readList(capabilitiesJson)) {
                caps.add(String.valueOf(item));
            }
            capabilities = caps;
        }
        return new Mission(
                rs.getString("s256"),
                Base64.getDecoder().decode(rs.getString("blob_b64")),
                MissionState.fromValue(rs.getString("state")),
                rs.getString("agent_id"),
                Instant.parse(rs.getString("approved_at")),
                rs.getString("owner_id"),
                rs.getString("approver"),
                rs.getString("description"),
                approvedTools,
                capabilities);
    }

    private static List<Object> readList(String json) {
        try {
            return Json.MAPPER.readValue(json, new com.fasterxml.jackson.core.type.TypeReference<List<Object>>() {});
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("corrupt JSON column", e);
        }
    }

    @Override
    public Mission getMission(String s256) {
        List<Mission> found = jdbc.query("SELECT * FROM ps_mission WHERE s256 = ?", (rs, rowNum) -> mapRow(rs), s256);
        return found.isEmpty() ? null : found.getFirst();
    }

    @Override
    public void setMission(Mission mission) {
        jdbc.update("DELETE FROM ps_mission WHERE s256 = ?", mission.s256());
        jdbc.update(
                "INSERT INTO ps_mission (s256, blob_b64, state, agent_id, approved_at, owner_id, approver, "
                        + "description, approved_tools_json, capabilities_json) VALUES (?,?,?,?,?,?,?,?,?,?)",
                mission.s256(),
                Base64.getEncoder().encodeToString(mission.blobBytes()),
                mission.state().value(),
                mission.agentId(),
                mission.approvedAt().toString(),
                mission.ownerId(),
                mission.approver(),
                mission.description(),
                mission.approvedTools() == null ? null : PendingSerde.write(mission.approvedTools()),
                mission.capabilities() == null ? null : PendingSerde.write(mission.capabilities()));
    }

    @Override
    public boolean hasMission(String s256) {
        Integer count = jdbc.queryForObject("SELECT COUNT(*) FROM ps_mission WHERE s256 = ?", Integer.class, s256);
        return count != null && count > 0;
    }

    @Override
    public List<Mission> listAllMissions() {
        return jdbc.query("SELECT * FROM ps_mission", (rs, rowNum) -> mapRow(rs));
    }

    @Override
    public void appendMissionLog(String s256, MissionLogEntry entry) {
        jdbc.update(
                "INSERT INTO ps_mission_log (s256, ts, kind, payload_json) VALUES (?,?,?,?)",
                s256,
                entry.ts().toString(),
                entry.kind().value(),
                PendingSerde.write(entry.payload()));
    }

    @Override
    public List<MissionLogEntry> getMissionLog(String s256) {
        return jdbc.query(
                "SELECT ts, kind, payload_json FROM ps_mission_log WHERE s256 = ? ORDER BY id",
                (rs, rowNum) -> new MissionLogEntry(
                        Instant.parse(rs.getString("ts")),
                        MissionLogKind.fromValue(rs.getString("kind")),
                        Json.readMap(rs.getString("payload_json"))),
                s256);
    }
}
