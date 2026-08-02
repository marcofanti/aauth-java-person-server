package io.github.marcofanti.aauth.personserver.persistence;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.personserver.model.AuthTokenResponse;
import io.github.marcofanti.aauth.personserver.model.InteractionTerminalResult;
import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionProposal;
import io.github.marcofanti.aauth.personserver.model.MissionRef;
import io.github.marcofanti.aauth.personserver.model.MissionState;
import io.github.marcofanti.aauth.personserver.model.PendingStatus;
import io.github.marcofanti.aauth.personserver.model.PendingStoreValue;
import io.github.marcofanti.aauth.personserver.model.RequirementLevel;
import io.github.marcofanti.aauth.personserver.model.TokenRequest;
import io.github.marcofanti.aauth.personserver.model.ToolSpec;
import io.github.marcofanti.aauth.personserver.ps.PendingRecord;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** PendingRecord / Mission ↔ JSON for SQL rows (Java-local format; see docs/PROGRESS.md). */
public final class PendingSerde {

    private PendingSerde() {}

    static String write(Object value) {
        try {
            return Json.MAPPER.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("serialization failed", e);
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> mapOrNull(Object value) {
        return value instanceof Map ? (Map<String, Object>) value : null;
    }

    static String stringOrNull(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    // --- Mission ---------------------------------------------------------------------

    public static Map<String, Object> missionToDict(Mission mission) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("s256", mission.s256());
        out.put("blob_b64", Base64.getEncoder().encodeToString(mission.blobBytes()));
        out.put("state", mission.state().value());
        out.put("agent_id", mission.agentId());
        out.put("approved_at", mission.approvedAt().toString());
        out.put("owner_id", mission.ownerId());
        out.put("approver", mission.approver());
        out.put("description", mission.description());
        out.put("approved_tools", mission.approvedTools());
        out.put("capabilities", mission.capabilities());
        return out;
    }

    @SuppressWarnings("unchecked")
    public static Mission missionFromDict(Map<String, Object> data) {
        List<Map<String, String>> approvedTools = (List<Map<String, String>>) data.get("approved_tools");
        List<String> capabilities = (List<String>) data.get("capabilities");
        return new Mission(
                String.valueOf(data.get("s256")),
                Base64.getDecoder().decode(String.valueOf(data.get("blob_b64"))),
                MissionState.fromValue(String.valueOf(data.get("state"))),
                String.valueOf(data.get("agent_id")),
                Instant.parse(String.valueOf(data.get("approved_at"))),
                stringOrNull(data.get("owner_id")),
                String.valueOf(data.get("approver")),
                String.valueOf(data.get("description")),
                approvedTools,
                capabilities);
    }

    // --- PendingRecord ---------------------------------------------------------------

    public static Map<String, Object> recordToDict(PendingRecord record) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("pending_id", record.pendingId);
        out.put("interaction_code", record.interactionCode);
        out.put("kind", record.kind);
        out.put("created_at", record.createdAt.toString());
        out.put("ttl_seconds", record.ttlSeconds);
        if (record.tokenRequest != null) {
            out.put("token_request", tokenRequestToDict(record.tokenRequest));
        }
        if (record.missionProposal != null) {
            out.put("mission_proposal", missionProposalToDict(record.missionProposal));
        }
        out.put("owner_id", record.ownerId);
        out.put("status", record.status.value());
        out.put("requirement", record.requirement == null ? null : record.requirement.value());
        out.put("clarification", record.clarification);
        out.put("timeout", record.timeout);
        out.put("options", record.options);
        if (record.terminal != null) {
            out.put("terminal", terminalToDict(record.terminal));
        }
        out.put("interaction_type", record.interactionType);
        out.put("interaction_summary", record.interactionSummary);
        out.put("interaction_question", record.interactionQuestion);
        out.put("relay_url", record.relayUrl);
        out.put("relay_code", record.relayCode);
        out.put("mission_s256", record.missionS256);
        out.put("pending_agent_id", record.pendingAgentId);
        out.put("interaction_description", record.interactionDescription);
        out.put("permission_action", record.permissionAction);
        out.put("permission_description", record.permissionDescription);
        out.put("permission_parameters", record.permissionParameters);
        out.put("failure", record.failure);
        out.put("gone", record.gone);
        out.put("delivered", record.delivered);
        out.put("clarification_responses", record.clarificationResponses);
        out.put("clarification_round", record.clarificationRound);
        out.put("callback_url", record.callbackUrl);
        out.put("verified_resource_claims", record.verifiedResourceClaims);
        out.put("token_agent_cnf_jwk", record.tokenAgentCnfJwk);
        out.put("evaluator_reason", record.evaluatorReason);
        return out;
    }

    @SuppressWarnings("unchecked")
    public static PendingRecord recordFromDict(Map<String, Object> data) {
        PendingRecord record = new PendingRecord(
                String.valueOf(data.get("pending_id")),
                String.valueOf(data.get("interaction_code")),
                String.valueOf(data.get("kind")),
                Instant.parse(String.valueOf(data.get("created_at"))),
                ((Number) data.get("ttl_seconds")).intValue());
        if (data.get("token_request") instanceof Map<?, ?> tokenRequest) {
            record.tokenRequest = tokenRequestFromDict((Map<String, Object>) tokenRequest);
        }
        if (data.get("mission_proposal") instanceof Map<?, ?> proposal) {
            record.missionProposal = missionProposalFromDict((Map<String, Object>) proposal);
        }
        record.ownerId = stringOrNull(data.get("owner_id"));
        record.status = PendingStatus.fromValue(String.valueOf(data.getOrDefault("status", "pending")));
        if (data.get("requirement") != null) {
            record.requirement = RequirementLevel.fromValue(String.valueOf(data.get("requirement")));
        }
        record.clarification = stringOrNull(data.get("clarification"));
        record.timeout = data.get("timeout") == null ? null : ((Number) data.get("timeout")).intValue();
        record.options = (List<String>) data.get("options");
        if (data.get("terminal") instanceof Map<?, ?> terminal) {
            record.terminal = terminalFromDict((Map<String, Object>) terminal);
        }
        record.interactionType = stringOrNull(data.get("interaction_type"));
        record.interactionSummary = stringOrNull(data.get("interaction_summary"));
        record.interactionQuestion = stringOrNull(data.get("interaction_question"));
        record.relayUrl = stringOrNull(data.get("relay_url"));
        record.relayCode = stringOrNull(data.get("relay_code"));
        record.missionS256 = stringOrNull(data.get("mission_s256"));
        record.pendingAgentId = stringOrNull(data.get("pending_agent_id"));
        record.interactionDescription = stringOrNull(data.get("interaction_description"));
        record.permissionAction = stringOrNull(data.get("permission_action"));
        record.permissionDescription = stringOrNull(data.get("permission_description"));
        record.permissionParameters = mapOrNull(data.get("permission_parameters"));
        record.failure = stringOrNull(data.get("failure"));
        record.gone = Boolean.TRUE.equals(data.get("gone"));
        record.delivered = Boolean.TRUE.equals(data.get("delivered"));
        if (data.get("clarification_responses") instanceof List<?> responses) {
            for (Object response : responses) {
                record.clarificationResponses.add(String.valueOf(response));
            }
        }
        record.clarificationRound =
                data.get("clarification_round") == null ? 0 : ((Number) data.get("clarification_round")).intValue();
        record.callbackUrl = stringOrNull(data.get("callback_url"));
        record.verifiedResourceClaims = mapOrNull(data.get("verified_resource_claims"));
        record.tokenAgentCnfJwk = mapOrNull(data.get("token_agent_cnf_jwk"));
        record.evaluatorReason = stringOrNull(data.get("evaluator_reason"));
        return record;
    }

    static Map<String, Object> tokenRequestToDict(TokenRequest request) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("agent_id", request.agentId());
        out.put("resource_token", request.resourceToken());
        out.put("justification", request.justification());
        out.put("upstream_token", request.upstreamToken());
        out.put("login_hint", request.loginHint());
        out.put("tenant", request.tenant());
        out.put("domain_hint", request.domainHint());
        if (request.mission() != null) {
            out.put(
                    "mission",
                    Map.of(
                            "approver",
                            request.mission().approver(),
                            "s256",
                            request.mission().s256()));
        }
        out.put("agent_cnf_jwk", request.agentCnfJwk());
        out.put("agent_jkt", request.agentJkt());
        out.put("secure_mode", request.secureMode());
        return out;
    }

    static TokenRequest tokenRequestFromDict(Map<String, Object> data) {
        MissionRef mission = null;
        if (data.get("mission") instanceof Map<?, ?> ref) {
            mission = new MissionRef(String.valueOf(ref.get("approver")), String.valueOf(ref.get("s256")));
        }
        return new TokenRequest(
                String.valueOf(data.get("agent_id")),
                String.valueOf(data.get("resource_token")),
                stringOrNull(data.get("justification")),
                stringOrNull(data.get("upstream_token")),
                stringOrNull(data.get("login_hint")),
                stringOrNull(data.get("tenant")),
                stringOrNull(data.get("domain_hint")),
                mission,
                mapOrNull(data.get("agent_cnf_jwk")),
                stringOrNull(data.get("agent_jkt")),
                !Boolean.FALSE.equals(data.get("secure_mode")));
    }

    static Map<String, Object> missionProposalToDict(MissionProposal proposal) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("agent_id", proposal.agentId());
        out.put("description", proposal.description());
        List<Map<String, String>> tools = new ArrayList<>();
        for (ToolSpec tool : proposal.tools()) {
            tools.add(Map.of("name", tool.name(), "description", tool.description()));
        }
        out.put("tools", tools);
        out.put("owner_hint", proposal.ownerHint());
        return out;
    }

    static MissionProposal missionProposalFromDict(Map<String, Object> data) {
        List<ToolSpec> tools = new ArrayList<>();
        if (data.get("tools") instanceof List<?> rawTools) {
            for (Object raw : rawTools) {
                if (raw instanceof Map<?, ?> tool) {
                    tools.add(new ToolSpec(String.valueOf(tool.get("name")), String.valueOf(tool.get("description"))));
                }
            }
        }
        return new MissionProposal(
                String.valueOf(data.get("agent_id")),
                String.valueOf(data.get("description")),
                tools,
                stringOrNull(data.get("owner_hint")));
    }

    static Map<String, Object> terminalToDict(PendingStoreValue terminal) {
        return switch (terminal) {
            case AuthTokenResponse token ->
                Map.of("type", "auth_token", "auth_token", token.authToken(), "expires_in", token.expiresIn());
            case Mission mission -> Map.of("type", "mission", "mission", missionToDict(mission));
            case InteractionTerminalResult interaction -> Map.of("type", "interaction", "body", interaction.body());
            default -> throw new IllegalArgumentException("unexpected terminal " + terminal.getClass());
        };
    }

    @SuppressWarnings("unchecked")
    static PendingStoreValue terminalFromDict(Map<String, Object> data) {
        return switch (String.valueOf(data.get("type"))) {
            case "auth_token" ->
                new AuthTokenResponse(
                        String.valueOf(data.get("auth_token")), ((Number) data.get("expires_in")).intValue());
            case "mission" -> missionFromDict((Map<String, Object>) data.get("mission"));
            case "interaction" -> new InteractionTerminalResult((Map<String, Object>) data.get("body"));
            default -> throw new IllegalArgumentException("unknown terminal type " + data.get("type"));
        };
    }
}
