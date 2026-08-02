package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionLogEntry;
import io.github.marcofanti.aauth.personserver.model.MissionLogKind;
import io.github.marcofanti.aauth.personserver.model.MissionOutcome;
import io.github.marcofanti.aauth.personserver.model.MissionProposal;
import io.github.marcofanti.aauth.personserver.model.PendingStoreValue;
import io.github.marcofanti.aauth.personserver.model.RequirementLevel;
import io.github.marcofanti.aauth.personserver.ps.PendingRequestStore.PendingUpdate;
import java.time.Instant;
import java.util.Map;

/** In-memory {@link MissionLifecycle}. */
public final class MemoryMissionLifecycle implements MissionLifecycle {

    private final MissionStatePort mission;
    private final PendingRequestStore pending;
    private final String psIssuer;
    private final boolean autoApproveMission;

    public MemoryMissionLifecycle(
            MissionStatePort mission, PendingRequestStore pending, String psIssuer, boolean autoApproveMission) {
        this.mission = mission;
        this.pending = pending;
        this.psIssuer = MissionUtils.stripTrailingSlash(psIssuer);
        this.autoApproveMission = autoApproveMission;
    }

    private void recordMission(Mission approved) {
        mission.setMission(approved);
        mission.appendMissionLog(
                approved.s256(),
                new MissionLogEntry(
                        Instant.now(), MissionLogKind.MISSION_APPROVED, Map.of("agent_id", approved.agentId())));
    }

    @Override
    public MissionOutcome createMission(MissionProposal proposal) {
        if (autoApproveMission) {
            Mission approved = MissionUtils.missionFromProposal(proposal, psIssuer);
            recordMission(approved);
            return approved;
        }
        String pendingId = pending.createPending(proposal);
        pending.updatePending(pendingId, PendingUpdate.ofRequirement(RequirementLevel.INTERACTION));
        PendingStoreValue out = pending.getPending(pendingId, false);
        if (!(out instanceof MissionOutcome outcome) || out instanceof Mission) {
            throw new IllegalStateException("unexpected mission before approval");
        }
        return outcome;
    }

    @Override
    public Mission getMission(String s256) {
        Mission found = mission.getMission(s256);
        if (found == null) {
            throw new NotFoundException();
        }
        return found;
    }
}
