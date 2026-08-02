package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionLogEntry;
import io.github.marcofanti.aauth.personserver.model.MissionState;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/** In-memory {@link MissionControl}. */
public final class MemoryMissionControl implements MissionControl {

    private final MissionStatePort mission;

    public MemoryMissionControl(MissionStatePort mission) {
        this.mission = mission;
    }

    @Override
    public List<Mission> listMissions(String agentId, MissionState state) {
        List<Mission> out = new ArrayList<>();
        for (Mission candidate : mission.listAllMissions()) {
            if (agentId != null && !candidate.agentId().equals(agentId)) {
                continue;
            }
            if (state != null && candidate.state() != state) {
                continue;
            }
            out.add(candidate);
        }
        out.sort(Comparator.comparing(Mission::approvedAt).reversed());
        return out;
    }

    @Override
    public List<Mission> listMissionsForOwner(String ownerId) {
        List<Mission> out = new ArrayList<>();
        for (Mission candidate : mission.listAllMissions()) {
            if (ownerId.equals(candidate.ownerId())) {
                out.add(candidate);
            }
        }
        out.sort(Comparator.comparing(Mission::approvedAt).reversed());
        return out;
    }

    @Override
    public Mission inspectMission(String s256) {
        Mission found = mission.getMission(s256);
        if (found == null) {
            throw new NotFoundException();
        }
        return found;
    }

    @Override
    public List<MissionLogEntry> missionLog(String s256) {
        if (!mission.hasMission(s256)) {
            throw new NotFoundException();
        }
        return mission.getMissionLog(s256);
    }

    @Override
    public Mission terminateMission(String s256) {
        Mission found = inspectMission(s256);
        if (found.state() != MissionState.ACTIVE) {
            throw new IllegalArgumentException("can only terminate an active mission");
        }
        Mission updated = found.withState(MissionState.TERMINATED);
        mission.setMission(updated);
        return updated;
    }
}
