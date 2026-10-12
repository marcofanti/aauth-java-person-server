package io.github.marcofanti.aauth.personserver.ps.web;

import io.github.marcofanti.aauth.personserver.model.AgentInteractionRequest;
import io.github.marcofanti.aauth.personserver.model.AuditRequest;
import io.github.marcofanti.aauth.personserver.model.DeferredResponse;
import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionOutcome;
import io.github.marcofanti.aauth.personserver.model.MissionProposal;
import io.github.marcofanti.aauth.personserver.model.MissionRef;
import io.github.marcofanti.aauth.personserver.model.PendingPollOutcome;
import io.github.marcofanti.aauth.personserver.model.PermissionOutcome;
import io.github.marcofanti.aauth.personserver.model.PermissionRequest;
import io.github.marcofanti.aauth.personserver.model.TokenRequest;
import io.github.marcofanti.aauth.personserver.model.ToolSpec;
import io.github.marcofanti.aauth.personserver.ps.Draft11MissionStatus;
import io.github.marcofanti.aauth.personserver.ps.MissionUtils;
import io.github.marcofanti.aauth.personserver.ps.PsContainer;
import io.github.marcofanti.aauth.personserver.ps.PsGovernance;
import io.github.marcofanti.aauth.personserver.ps.web.HttpSigAuth.SignedRequest;
import io.github.marcofanti.aauth.personserver.web.AAuthResponses;
import io.github.marcofanti.aauth.personserver.web.BodyReader;
import io.github.marcofanti.aauth.personserver.web.BodyValidationException;
import io.github.marcofanti.aauth.personserver.web.HttpError;
import io.github.marcofanti.aauth.personserver.web.ProblemError;
import io.github.marcofanti.aauth.personserver.web.RequestExtract;
import io.github.marcofanti.aauth.personserver.web.Sanitize;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/** Agent-facing protocol routes: mission, token, permission, audit, interaction, pending. */
@Profile({"default", "portal", "ps"})
@RestController
public class PsAgentController {

    private static final Set<String> INTERACTION_TYPES = Set.of("interaction", "payment", "question", "completion");

    private final PsContainer ps;
    private final PsAuth auth;
    private final String psOrigin;
    private final Draft11MissionStatus missionStatus;

    public PsAgentController(PsContainer ps, PsAuth auth, PsSettings settings) {
        this.ps = ps;
        this.auth = auth;
        this.psOrigin = MissionUtils.stripTrailingSlash(settings.origin());
        this.missionStatus = new Draft11MissionStatus(ps.mission());
    }

    /**
     * Draft-11 names a mission by {@code mission_s256} (§8.2.1, checked for ownership, expiry and
     * termination); draft-10 by the {@code {approver, s256}} object.
     */
    private MissionRef missionParameter(BodyReader body, String agentId) {
        String s256 = body.optString("mission_s256");
        if (s256 != null) {
            missionStatus.requireActiveParameter(s256, agentId);
            return new MissionRef(psOrigin, s256);
        }
        return missionRef(body.optMap("mission"));
    }

    static MissionRef missionRef(Map<String, Object> mission) {
        if (mission == null) {
            return null;
        }
        Object approver = mission.get("approver");
        Object s256 = mission.get("s256");
        if (!(approver instanceof String) || !(s256 instanceof String)) {
            throw new BodyValidationException("mission requires approver and s256");
        }
        return new MissionRef((String) approver, (String) s256);
    }

    @PostMapping("/mission")
    public ResponseEntity<Object> postMission(HttpServletRequest request, @RequestBody(required = false) byte[] raw) {
        SignedRequest signed = RequestExtract.signedRequest(request, raw);
        String agentId = auth.requireAgentId(signed);
        BodyReader body = BodyReader.parse(raw);
        String description = body.requireString("description");
        List<ToolSpec> tools = new ArrayList<>();
        List<Object> toolList = body.optList("tools");
        if (toolList != null) {
            for (Object item : toolList) {
                if (!(item instanceof Map<?, ?> tool)
                        || !(tool.get("name") instanceof String name)
                        || !(tool.get("description") instanceof String toolDescription)) {
                    throw new BodyValidationException("tools entries require name and description");
                }
                tools.add(new ToolSpec(name, toolDescription));
            }
        }
        MissionProposal proposal =
                new MissionProposal(agentId, Sanitize.markdown(description), tools, body.optString("owner_hint"));
        MissionOutcome outcome = ps.lifecycle().createMission(proposal);
        return switch (outcome) {
            case Mission mission -> AAuthResponses.missionApprovalResponse(mission);
            case DeferredResponse deferred -> AAuthResponses.jsonDeferred(deferred);
        };
    }

    /** Draft-10 token endpoint ({@code token_endpoint}); kept for dual-stack clients. */
    @PostMapping("/token")
    public ResponseEntity<Object> postToken(HttpServletRequest request, @RequestBody(required = false) byte[] raw) {
        SignedRequest signed = RequestExtract.signedRequest(request, raw);
        PsAuth.TokenAgentContext agent = auth.requireTokenAgent(signed);
        BodyReader body = BodyReader.parse(raw);
        MissionRef mission = missionRef(body.optMap("mission"));
        if (mission == null) {
            mission = MissionHeader.parseAAuthMissionHeader(signed.header("aauth-mission"));
        }
        TokenRequest tokenRequest = tokenRequest(agent, body, mission, null);
        return AAuthResponses.tokenOutcomeResponse(ps.tokenBroker().requestToken(tokenRequest));
    }

    /**
     * Draft-11 {@code auth_token_endpoint} (§7.2.1): {@code presented_token} is REQUIRED and the
     * mission comes from the verified resource token. Errors are problem+json.
     */
    @PostMapping("/auth-token")
    public ResponseEntity<Object> postAuthToken(HttpServletRequest request, @RequestBody(required = false) byte[] raw) {
        SignedRequest signed = RequestExtract.signedRequest(request, raw);
        PsAuth.TokenAgentContext agent = auth.requireTokenAgent(signed);
        BodyCoverage.require(signed);
        BodyReader body;
        String presentedToken;
        try {
            body = BodyReader.parse(raw);
            body.requireString("resource_token");
            presentedToken = body.requireString("presented_token");
        } catch (BodyValidationException e) {
            throw new ProblemError(400, "invalid_request", e.getMessage());
        }
        TokenRequest tokenRequest =
                tokenRequest(agent, body, null, new TokenRequest.Draft11(presentedToken, agent.agentTokenExp()));
        return AAuthResponses.tokenOutcomeResponse(ps.tokenBroker().requestToken(tokenRequest));
    }

    private static TokenRequest tokenRequest(
            PsAuth.TokenAgentContext agent, BodyReader body, MissionRef mission, TokenRequest.Draft11 draft11) {
        return TokenRequest.builder(agent.agentId(), body.requireString("resource_token"))
                .justification(Sanitize.markdownOrNull(body.optString("justification")))
                .upstreamToken(body.optString("upstream_token"))
                .loginHint(body.optString("login_hint"))
                .tenant(body.optString("tenant"))
                .domainHint(body.optString("domain_hint"))
                .mission(mission)
                .agentCnfJwk(agent.agentCnfJwk())
                .agentJkt(agent.agentJkt())
                .secureMode(agent.secureMode())
                .draft11(draft11)
                .build();
    }

    @PostMapping("/permission")
    public ResponseEntity<Object> postPermission(
            HttpServletRequest request, @RequestBody(required = false) byte[] raw) {
        SignedRequest signed = RequestExtract.signedRequest(request, raw);
        String agentId = auth.requireAgentId(signed);
        BodyReader body = BodyReader.parse(raw);
        PermissionRequest permission = new PermissionRequest(
                body.requireString("action"),
                Sanitize.markdownOrNull(body.optString("description")),
                body.optMap("parameters"),
                missionParameter(body, agentId),
                agentId);
        PsGovernance.PermissionResponse outcome = ps.governance().postPermission(permission);
        return switch (outcome) {
            case PsGovernance.PermissionResponse.Deferred deferred -> AAuthResponses.jsonDeferred(deferred.deferred());
            case PsGovernance.PermissionResponse.Granted granted -> {
                PermissionOutcome value = granted.outcome();
                Map<String, Object> payload = new LinkedHashMap<>();
                payload.put("permission", value.permission());
                if (value.reason() != null) {
                    payload.put("reason", value.reason());
                }
                yield ResponseEntity.ok(payload);
            }
        };
    }

    @PostMapping("/audit")
    public ResponseEntity<Void> postAudit(HttpServletRequest request, @RequestBody(required = false) byte[] raw) {
        SignedRequest signed = RequestExtract.signedRequest(request, raw);
        String agentId = auth.requireAgentId(signed);
        BodyReader body = BodyReader.parse(raw);
        if (body.optString("mission_s256") == null && body.optMap("mission") == null) {
            throw new BodyValidationException("field 'mission_s256' (or draft-10 'mission') required");
        }
        AuditRequest audit = new AuditRequest(
                missionParameter(body, agentId),
                body.requireString("action"),
                Sanitize.markdownOrNull(body.optString("description")),
                body.optMap("parameters"),
                body.optMap("result"),
                agentId);
        ps.governance().postAudit(audit);
        return ResponseEntity.status(201).build();
    }

    @PostMapping("/interaction")
    public ResponseEntity<Object> postAgentInteraction(
            HttpServletRequest request, @RequestBody(required = false) byte[] raw) {
        SignedRequest signed = RequestExtract.signedRequest(request, raw);
        String agentId = auth.requireAgentId(signed);
        BodyReader body = BodyReader.parse(raw);
        String type = body.requireString("type");
        if (!INTERACTION_TYPES.contains(type)) {
            throw new BodyValidationException("type must be one of interaction, payment, question, completion");
        }
        if ("completion".equals(type) && body.optString("mission_s256") != null) {
            throw new ProblemError(
                    400, "invalid_request", "draft-11 completion is POST {mission_endpoint}/{mission_s256} (§8.5)");
        }
        AgentInteractionRequest interaction = new AgentInteractionRequest(
                type,
                Sanitize.markdownOrNull(body.optString("description")),
                body.optString("url"),
                body.optString("code"),
                Sanitize.markdownOrNull(body.optString("question")),
                Sanitize.markdownOrNull(body.optString("summary")),
                missionParameter(body, agentId),
                agentId);
        DeferredResponse deferred;
        try {
            deferred = ps.governance().postAgentInteraction(interaction);
        } catch (IllegalArgumentException e) {
            throw new HttpError(400, e.getMessage());
        }
        return AAuthResponses.jsonDeferred(deferred);
    }

    @GetMapping("/pending/{pendingId}")
    public ResponseEntity<Object> getPending(HttpServletRequest request, @PathVariable("pendingId") String pendingId) {
        SignedRequest signed = RequestExtract.signedRequest(request, null);
        String agentId = auth.requireAgentId(signed);
        PendingPollOutcome outcome = ps.tokenBroker().getPending(pendingId, agentId);
        return AAuthResponses.tokenOutcomeResponse(outcome);
    }

    @PostMapping("/pending/{pendingId}")
    public ResponseEntity<Object> postPending(
            HttpServletRequest request,
            @PathVariable("pendingId") String pendingId,
            @RequestBody(required = false) byte[] raw) {
        SignedRequest signed = RequestExtract.signedRequest(request, raw);
        String agentId = auth.requireAgentId(signed);
        BodyReader body = BodyReader.parse(raw);
        boolean hasClarification = body.has("clarification_response");
        boolean hasToken = body.has("resource_token");
        if (hasClarification == hasToken) {
            throw new BodyValidationException("Provide either clarification_response or resource_token, not both");
        }
        DeferredResponse outcome;
        if (hasClarification) {
            String clarification = Sanitize.markdown(body.requireString("clarification_response"));
            outcome = ps.tokenBroker().postClarificationResponse(pendingId, agentId, clarification);
        } else {
            String justification = Sanitize.markdownOrNull(body.optString("justification"));
            outcome = ps.tokenBroker()
                    .postUpdatedRequest(
                            pendingId,
                            agentId,
                            body.requireString("resource_token"),
                            justification,
                            body.optString("presented_token"));
        }
        return AAuthResponses.jsonDeferred(outcome);
    }

    @DeleteMapping("/pending/{pendingId}")
    public ResponseEntity<Void> deletePending(HttpServletRequest request, @PathVariable("pendingId") String pendingId) {
        SignedRequest signed = RequestExtract.signedRequest(request, null);
        String agentId = auth.requireAgentId(signed);
        ps.tokenBroker().cancelRequest(pendingId, agentId);
        return ResponseEntity.status(204).build();
    }
}
