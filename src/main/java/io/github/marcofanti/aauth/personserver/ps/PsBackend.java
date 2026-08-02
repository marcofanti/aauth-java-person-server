package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionLogEntry;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Mutable in-memory state shared by Person Server service implementations. */
public final class PsBackend implements MissionStatePort {

    private final Map<String, Mission> missions = new LinkedHashMap<>();
    private final Map<String, List<MissionLogEntry>> missionLog = new LinkedHashMap<>();
    final Map<String, PendingRecord> pending = new LinkedHashMap<>();
    final Map<String, String> codeIndex = new LinkedHashMap<>();

    @Override
    public synchronized Mission getMission(String s256) {
        return missions.get(s256);
    }

    @Override
    public synchronized void setMission(Mission mission) {
        missions.put(mission.s256(), mission);
    }

    @Override
    public synchronized boolean hasMission(String s256) {
        return missions.containsKey(s256);
    }

    @Override
    public synchronized List<Mission> listAllMissions() {
        return List.copyOf(missions.values());
    }

    @Override
    public synchronized void appendMissionLog(String s256, MissionLogEntry entry) {
        missionLog.computeIfAbsent(s256, key -> new ArrayList<>()).add(entry);
    }

    @Override
    public synchronized List<MissionLogEntry> getMissionLog(String s256) {
        return List.copyOf(missionLog.getOrDefault(s256, List.of()));
    }
}
