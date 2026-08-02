package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionLogEntry;
import java.util.List;

/** Port for mission + mission log storage (in-memory or SQL). */
public interface MissionStatePort {

    /** Return the mission or null when unknown. */
    Mission getMission(String s256);

    void setMission(Mission mission);

    boolean hasMission(String s256);

    List<Mission> listAllMissions();

    void appendMissionLog(String s256, MissionLogEntry entry);

    List<MissionLogEntry> getMissionLog(String s256);
}
