package io.github.marcofanti.aauth.personserver.ps.web;

import io.github.marcofanti.aauth.personserver.model.AuthTokenResponse;
import io.github.marcofanti.aauth.personserver.model.ConsentContext;
import io.github.marcofanti.aauth.personserver.model.DeferredResponse;
import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionState;
import io.github.marcofanti.aauth.personserver.ps.MissionUtils;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Map domain models to protocol-shaped JSON (byte parity with the Python encoder). */
public final class PsEncoding {

    private PsEncoding() {}

    public static Map<String, Object> missionListDict(Mission mission) {
        Map<String, Object> out = new LinkedHashMap<>(MissionUtils.missionBlobDict(mission));
        out.put("s256", mission.s256());
        out.put("state", mission.state().value());
        out.put("owner_id", mission.ownerId());
        return out;
    }

    public static Map<String, Object> missionDetailDict(Mission mission) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mission", missionListDict(mission));
        return out;
    }

    public static Map<String, Object> authTokenHttpDict(AuthTokenResponse token) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("auth_token", token.authToken());
        out.put("expires_in", token.expiresIn());
        return out;
    }

    public static Map<String, Object> consentContextHttpDict(ConsentContext context) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("pending_id", context.pendingId());
        payload.put("scopes", context.scopes());
        payload.put("mission", context.mission() != null ? missionListDict(context.mission()) : null);
        putIfNotNull(payload, "pending_kind", context.pendingKind());
        putIfNotNull(payload, "resource_name", context.resourceName());
        putIfNotNull(payload, "justification", context.justification());
        putIfNotNull(payload, "agent_name", context.agentName());
        if (context.clarificationResponses() != null
                && !context.clarificationResponses().isEmpty()) {
            payload.put("clarification_responses", new ArrayList<>(context.clarificationResponses()));
        }
        putIfNotNull(payload, "interaction_type", context.interactionType());
        putIfNotNull(payload, "summary", context.summary());
        putIfNotNull(payload, "question", context.question());
        putIfNotNull(payload, "resource_iss", context.resourceIss());
        putIfNotNull(payload, "resource_scope", context.resourceScope());
        putIfNotNull(payload, "resource_mission_s256", context.resourceMissionS256());
        putIfNotNull(payload, "permission_action", context.permissionAction());
        putIfNotNull(payload, "permission_description", context.permissionDescription());
        putIfNotNull(payload, "permission_parameters", context.permissionParameters());
        putIfNotNull(payload, "evaluator_reason", context.evaluatorReason());
        return payload;
    }

    /**
     * JSON body for 202 deferred responses. Clients such as {@code aauth.agent.poller} read
     * {@code requirement} and {@code code} from the body to drive callbacks (not only from
     * {@code AAuth-Requirement}); omitting them breaks interaction/consent flows.
     */
    public static Map<String, Object> deferredBodyDict(DeferredResponse deferred) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", deferred.status().value());
        if (deferred.requirement() != null) {
            body.put("requirement", deferred.requirement().value());
        }
        putIfNotNull(body, "code", deferred.code());
        putIfNotNull(body, "interaction_url", deferred.interactionUrl());
        body.put("retry_after", deferred.retryAfter());
        if (deferred.pendingId() != null && !deferred.pendingId().isEmpty()) {
            body.put("pending_id", deferred.pendingId());
        }
        if (deferred.pendingUrl() != null && !deferred.pendingUrl().isEmpty()) {
            body.put("pending_url", deferred.pendingUrl());
        }
        putIfNotNull(body, "clarification", deferred.clarification());
        putIfNotNull(body, "timeout", deferred.timeout());
        putIfNotNull(body, "options", deferred.options());
        return body;
    }

    public static String buildAAuthRequirementHeader(DeferredResponse deferred) {
        if (deferred.requirement() == null) {
            return null;
        }
        List<String> parts = new ArrayList<>();
        parts.add("requirement=" + deferred.requirement().value());
        if (deferred.interactionUrl() != null && deferred.code() != null) {
            parts.add("url=\"" + deferred.interactionUrl() + "\"");
            parts.add("code=\"" + deferred.code() + "\"");
        }
        return String.join("; ", parts);
    }

    public static MissionState missionStateFromQuery(String raw) {
        if (raw == null || raw.isEmpty()) {
            return null;
        }
        return MissionState.fromValue(raw);
    }

    private static void putIfNotNull(Map<String, Object> map, String key, Object value) {
        if (value != null) {
            map.put(key, value);
        }
    }
}
