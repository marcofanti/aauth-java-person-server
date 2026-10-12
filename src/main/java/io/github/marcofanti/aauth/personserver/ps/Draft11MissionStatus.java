package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionLogEntry;
import io.github.marcofanti.aauth.personserver.model.MissionLogKind;
import io.github.marcofanti.aauth.personserver.model.MissionState;
import io.github.marcofanti.aauth.personserver.web.ProblemError;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Draft-11 mission status (§8.6–8.8): active checks on every decision path, expiry as
 * termination, and termination reasons kept in the mission log beside the immutable blob.
 */
public final class Draft11MissionStatus {

    private static final Pattern S256 = Pattern.compile("[A-Za-z0-9_-]{43}");

    private final MissionStatePort missions;

    public Draft11MissionStatus(MissionStatePort missions) {
        this.missions = missions;
    }

    /** The mission's {@code expires_at}, or {@code null} when it has none. */
    public static Instant expiresAt(Mission mission) {
        Object value = MissionUtils.missionBlobDict(mission).get("expires_at");
        return value instanceof String text ? Instant.parse(text) : null;
    }

    /** A draft-11 blob names no approver: the approver is always the issuing PS (§8.2.1). */
    public static boolean isDraft11(Mission mission) {
        return !MissionUtils.missionBlobDict(mission).containsKey("approver");
    }

    /**
     * The agent's own active mission at its mission URL (§8.7): a missing mission and another
     * agent's mission get the same {@code mission_not_found}.
     */
    public Mission requireOwnActive(String s256, String agentId) {
        if (s256 == null || !S256.matcher(s256).matches()) {
            throw new ProblemError(400, "invalid_request", "the mission_s256 path segment is malformed");
        }
        Mission mission = missions.getMission(s256);
        boolean owned = mission != null && agentId.equals(mission.agentId());
        if (!owned) {
            throw new ProblemError(404, "mission_not_found", "no such mission for this agent");
        }
        return requireActive(mission);
    }

    /**
     * {@code mission_s256} named as a request parameter (§8.8): the mission must exist, belong to
     * {@code agentId}, and be active; an expired mission is terminated here, for good.
     */
    public Mission requireActiveParameter(String s256, String agentId) {
        Mission mission = missions.getMission(s256);
        if (mission == null || !Objects.equals(agentId, mission.agentId())) {
            throw new ProblemError(400, "invalid_request", "mission_s256 does not name a mission of this agent");
        }
        return requireActive(mission);
    }

    /** Any active draft-11 mission check: expiry is enforced on every decision path (§8.2). */
    public Mission requireActive(Mission mission) {
        if (mission.state() != MissionState.ACTIVE) {
            throw new MissionTerminatedException(terminationReason(mission.s256()));
        }
        Instant expires = isDraft11(mission) ? expiresAt(mission) : null;
        if (expires != null && !Instant.now().isBefore(expires)) {
            terminate(mission, "expired");
            throw new MissionTerminatedException("expired");
        }
        return mission;
    }

    /** End the mission for good and record why (§8.6); a terminated mission never reactivates. */
    public void terminate(Mission mission, String reason) {
        if (mission.state() != MissionState.ACTIVE) {
            return;
        }
        missions.setMission(mission.withState(MissionState.TERMINATED));
        recordReason(mission, reason);
    }

    /** Record why a draft-11 mission ended (§8.6); draft-10 missions keep the reference log shape. */
    public void recordReason(Mission mission, String reason) {
        if (isDraft11(mission)) {
            missions.appendMissionLog(
                    mission.s256(),
                    new MissionLogEntry(Instant.now(), MissionLogKind.MISSION_TERMINATED, Map.of("reason", reason)));
        }
    }

    /** The most recent recorded termination reason, or {@code null}. */
    public String terminationReason(String s256) {
        String reason = null;
        for (MissionLogEntry entry : missions.getMissionLog(s256)) {
            if (entry.kind() == MissionLogKind.MISSION_TERMINATED
                    && entry.payload().get("reason") instanceof String r) {
                reason = r;
            }
        }
        return reason;
    }

    /** Latest {@code exp} a token issued under {@code mission} may carry, or {@code null}. */
    public static Long capFor(Mission mission) {
        if (mission == null || !isDraft11(mission)) {
            return null;
        }
        Instant expires = expiresAt(mission);
        return expires == null ? null : expires.getEpochSecond();
    }
}
