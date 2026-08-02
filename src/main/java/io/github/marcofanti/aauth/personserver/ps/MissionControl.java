package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionLogEntry;
import io.github.marcofanti.aauth.personserver.model.MissionState;
import java.util.List;

/** List, inspect, and lifecycle operations for missions (protocol §Mission Control). */
public interface MissionControl {

    /** Filter missions by agent and/or state; null filters match all. */
    List<Mission> listMissions(String agentId, MissionState state);

    /** Missions whose ownerId matches (legal user scope). */
    List<Mission> listMissionsForOwner(String ownerId);

    /** Detail view. */
    Mission inspectMission(String s256);

    /** Ordered mission log entries. */
    List<MissionLogEntry> missionLog(String s256);

    /** Set mission to terminated (only transition from active). */
    Mission terminateMission(String s256);
}
