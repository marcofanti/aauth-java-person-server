package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.model.AgentInteractionRequest;
import io.github.marcofanti.aauth.personserver.model.AuditRequest;
import io.github.marcofanti.aauth.personserver.model.DeferredResponse;
import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionLogEntry;
import io.github.marcofanti.aauth.personserver.model.MissionLogKind;
import io.github.marcofanti.aauth.personserver.model.PendingStoreValue;
import io.github.marcofanti.aauth.personserver.model.PermissionOutcome;
import io.github.marcofanti.aauth.personserver.model.PermissionRequest;
import io.github.marcofanti.aauth.personserver.model.RequirementLevel;
import io.github.marcofanti.aauth.personserver.ps.PendingRequestStore.InteractionPendingSpec;
import io.github.marcofanti.aauth.personserver.ps.PendingRequestStore.PendingUpdate;
import io.github.marcofanti.aauth.personserver.ps.PendingRequestStore.PermissionPendingSpec;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Permission, audit, and agent interaction (SPEC §Permission, §Audit, §Interaction). */
public final class PsGovernance {

    /** {@code POST /permission} result: immediate outcome or deferred user decision. */
    public sealed interface PermissionResponse {
        record Granted(PermissionOutcome outcome) implements PermissionResponse {}

        record Deferred(DeferredResponse deferred) implements PermissionResponse {}
    }

    private final MissionStatePort mission;
    private final PendingRequestStore store;

    public PsGovernance(MissionStatePort mission, PendingRequestStore store) {
        this.mission = mission;
        this.store = store;
    }

    private static boolean actionInApprovedTools(String action, List<Map<String, String>> approvedTools) {
        if (approvedTools == null || approvedTools.isEmpty()) {
            return false;
        }
        for (Map<String, String> tool : approvedTools) {
            if (action.equals(tool.get("name"))) {
                return true;
            }
        }
        return false;
    }

    public PermissionResponse postPermission(PermissionRequest request) {
        // No mission: spec-permissive — grant. Log only when mission is present.
        if (request.mission() == null) {
            return new PermissionResponse.Granted(PermissionOutcome.granted());
        }

        Mission active = MissionGuards.requireActiveMission(mission, request.mission());

        if (actionInApprovedTools(request.action(), active.approvedTools())) {
            Map<String, Object> payload = new HashMap<>();
            payload.put("action", request.action());
            payload.put("description", request.description());
            payload.put("parameters", request.parameters());
            payload.put("result", "granted");
            payload.put("decided_by", "approved_tools");
            mission.appendMissionLog(
                    active.s256(), new MissionLogEntry(Instant.now(), MissionLogKind.PERMISSION, payload));
            return new PermissionResponse.Granted(PermissionOutcome.granted());
        }

        // Action is outside approved_tools — escalate to the user.
        String pendingId = store.createPermissionPending(new PermissionPendingSpec(
                request.agentId(),
                active.ownerId(),
                active.s256(),
                request.action(),
                request.description(),
                request.parameters()));
        store.updatePending(pendingId, PendingUpdate.ofRequirement(RequirementLevel.INTERACTION));
        Map<String, Object> payload = new HashMap<>();
        payload.put("action", request.action());
        payload.put("description", request.description());
        payload.put("parameters", request.parameters());
        payload.put("result", "deferred");
        payload.put("decided_by", "user_pending");
        payload.put("pending_id", pendingId);
        mission.appendMissionLog(active.s256(), new MissionLogEntry(Instant.now(), MissionLogKind.PERMISSION, payload));
        PendingStoreValue out = store.getPending(pendingId, false);
        if (out instanceof DeferredResponse deferred) {
            return new PermissionResponse.Deferred(deferred);
        }
        throw new IllegalStateException("unexpected terminal on new permission pending");
    }

    public void postAudit(AuditRequest request) {
        Mission active = MissionGuards.requireActiveMission(mission, request.mission());
        Map<String, Object> payload = new HashMap<>();
        payload.put("action", request.action());
        payload.put("description", request.description());
        payload.put("parameters", request.parameters());
        payload.put("result", request.result());
        mission.appendMissionLog(active.s256(), new MissionLogEntry(Instant.now(), MissionLogKind.AUDIT, payload));
    }

    public DeferredResponse postAgentInteraction(AgentInteractionRequest request) {
        String missionS256 = null;
        String ownerId = null;
        if (request.mission() != null) {
            Mission active = MissionGuards.requireActiveMission(mission, request.mission());
            missionS256 = active.s256();
            ownerId = active.ownerId();
            Map<String, Object> payload = new HashMap<>();
            payload.put("type", request.type());
            payload.put("description", request.description());
            mission.appendMissionLog(
                    active.s256(), new MissionLogEntry(Instant.now(), MissionLogKind.AGENT_INTERACTION, payload));
        } else if ("completion".equals(request.type())) {
            throw new IllegalArgumentException("completion requires mission");
        }

        String pendingId = store.createInteractionPending(new InteractionPendingSpec(
                request.agentId(),
                request.type(),
                ownerId,
                missionS256,
                request.summary(),
                request.question(),
                request.url(),
                request.code(),
                request.description()));
        store.updatePending(pendingId, PendingUpdate.ofRequirement(RequirementLevel.INTERACTION));
        PendingStoreValue out = store.getPending(pendingId, false);
        if (out instanceof DeferredResponse deferred) {
            return deferred;
        }
        throw new IllegalStateException("unexpected terminal on new interaction pending");
    }
}
