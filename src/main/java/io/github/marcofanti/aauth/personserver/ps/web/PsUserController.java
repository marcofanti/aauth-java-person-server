package io.github.marcofanti.aauth.personserver.ps.web;

import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.ps.ForbiddenOwnerException;
import io.github.marcofanti.aauth.personserver.ps.MemoryPendingStore;
import io.github.marcofanti.aauth.personserver.ps.PendingRecord;
import io.github.marcofanti.aauth.personserver.ps.PsContainer;
import io.github.marcofanti.aauth.personserver.web.HttpError;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/** Legal-user mission control and consent queue ({@code /user/*}). */
@Profile({"default", "portal", "ps"})
@RestController
public class PsUserController {

    private final PsContainer ps;
    private final PsAuth auth;

    public PsUserController(PsContainer ps, PsAuth auth) {
        this.ps = ps;
        this.auth = auth;
    }

    private Mission requireOwnedMission(String s256, String userId) {
        Mission mission = ps.missionControl().inspectMission(s256);
        if (mission.ownerId() == null || !mission.ownerId().equals(userId)) {
            throw new ForbiddenOwnerException();
        }
        return mission;
    }

    @GetMapping("/user/missions")
    public List<Map<String, Object>> listUserMissions(
            @RequestHeader(value = "Authorization", required = false) String authorization) {
        String userId = auth.requireUser(authorization);
        List<Map<String, Object>> out = new ArrayList<>();
        for (Mission mission : ps.missionControl().listMissionsForOwner(userId)) {
            out.add(PsEncoding.missionListDict(mission));
        }
        return out;
    }

    @GetMapping("/user/missions/{s256}")
    public Map<String, Object> inspectUserMission(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @PathVariable("s256") String s256) {
        String userId = auth.requireUser(authorization);
        Mission mission = requireOwnedMission(s256, userId);
        return PsAdminController.missionDetailWithLog(
                mission, ps.missionControl().missionLog(s256));
    }

    @PatchMapping("/user/missions/{s256}")
    public Map<String, Object> patchUserMission(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @PathVariable("s256") String s256,
            @RequestBody(required = false) byte[] raw) {
        String userId = auth.requireUser(authorization);
        requireOwnedMission(s256, userId);
        PsAdminController.requireTerminatedState(raw);
        Mission mission;
        try {
            mission = ps.missionControl().terminateMission(s256);
        } catch (IllegalArgumentException e) {
            throw new HttpError(400, e.getMessage());
        }
        return PsEncoding.missionDetailDict(mission);
    }

    @GetMapping("/user/consent")
    public List<Map<String, Object>> listUserConsent(
            @RequestHeader(value = "Authorization", required = false) String authorization) {
        String userId = auth.requireUser(authorization);
        String interactionUrl = ps.pendingStore().interactionBaseUrl() + MemoryPendingStore.CONSENT_UI_PATH;
        List<Map<String, Object>> out = new ArrayList<>();
        for (PendingRecord record : ps.pendingStore().listInteractionPendingForOwner(userId)) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("pending_id", record.pendingId);
            row.put("code", record.interactionCode);
            row.put("kind", record.kind);
            row.put("agent_id", record.agentId() != null ? record.agentId() : "");
            row.put("interaction_url", interactionUrl);
            out.add(row);
        }
        return out;
    }
}
