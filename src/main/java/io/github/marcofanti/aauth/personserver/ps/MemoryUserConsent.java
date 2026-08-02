package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.personserver.model.AuthTokenResponse;
import io.github.marcofanti.aauth.personserver.model.ConsentContext;
import io.github.marcofanti.aauth.personserver.model.DecisionResult;
import io.github.marcofanti.aauth.personserver.model.InteractionTerminalResult;
import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionLogEntry;
import io.github.marcofanti.aauth.personserver.model.MissionLogKind;
import io.github.marcofanti.aauth.personserver.model.MissionState;
import io.github.marcofanti.aauth.personserver.model.PendingStatus;
import io.github.marcofanti.aauth.personserver.model.RequirementLevel;
import io.github.marcofanti.aauth.personserver.model.TokenOutcome;
import io.github.marcofanti.aauth.personserver.model.TokenRequest;
import io.github.marcofanti.aauth.personserver.model.UserDecision;
import io.github.marcofanti.aauth.personserver.ps.PendingRequestStore.PendingUpdate;
import io.github.marcofanti.aauth.tokens.ResourceTokens;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** In-memory {@link UserConsent}. */
public final class MemoryUserConsent implements UserConsent {

    private static final Logger log = LoggerFactory.getLogger(MemoryUserConsent.class);

    private final MissionStatePort mission;
    private final PendingRequestStore store;
    private final AsFederator federator;
    private final AuthTokenIssuer authIssuer;
    private final String agentJwtStub;
    private final String psIssuer;
    private final Function<String, Map<String, Object>> resourceJwks;

    public MemoryUserConsent(
            MissionStatePort mission,
            PendingRequestStore store,
            AsFederator federator,
            AuthTokenIssuer authIssuer,
            String agentJwtStub,
            String psIssuer,
            Function<String, Map<String, Object>> resourceJwks) {
        this.mission = mission;
        this.store = store;
        this.federator = federator;
        this.authIssuer = authIssuer;
        this.agentJwtStub = agentJwtStub;
        this.psIssuer = MissionUtils.stripTrailingSlash(psIssuer);
        this.resourceJwks = resourceJwks;
    }

    /** Prefer a fresh verify of resource_token so aud / claims match JWT reality. */
    private Map<String, Object> resolvedResourceClaims(PendingRecord record, TokenRequest tokenRequest) {
        if (!tokenRequest.secureMode()) {
            return null;
        }
        if (resourceJwks != null) {
            try {
                return ResourceTokens.verify(
                        tokenRequest.resourceToken(),
                        resourceJwks,
                        null,
                        tokenRequest.agentId(),
                        tokenRequest.agentJkt());
            } catch (TokenException e) {
                log.info("consent: re-verify resource_token failed ({}), using stored claims if any", e.getMessage());
            }
        }
        return record.verifiedResourceClaims;
    }

    private void recordMission(Mission approved) {
        mission.setMission(approved);
        mission.appendMissionLog(
                approved.s256(),
                new MissionLogEntry(
                        Instant.now(), MissionLogKind.MISSION_APPROVED, Map.of("agent_id", approved.agentId())));
    }

    @Override
    public ConsentContext getConsentContext(String code) {
        PendingRecord record = store.lookupCode(code);
        String justification = record.tokenRequest != null ? record.tokenRequest.justification() : null;
        Mission found = findMissionFor(record);
        List<String> responses = List.copyOf(record.clarificationResponses);
        Map<String, Object> claims = record.verifiedResourceClaims == null ? Map.of() : record.verifiedResourceClaims;
        String resourceIss = nonEmpty(claims.get("iss"));
        String resourceScope = nonEmpty(claims.get("scope"));
        String resourceMissionS256 = null;
        if (claims.get("mission") instanceof Map<?, ?> claimMission && claimMission.get("s256") != null) {
            resourceMissionS256 = String.valueOf(claimMission.get("s256"));
        }
        if ("interaction".equals(record.kind)) {
            return ConsentContext.builder(record.pendingId)
                    .justification(record.interactionDescription)
                    .mission(found)
                    .clarificationResponses(responses)
                    .interactionType(record.interactionType)
                    .summary(record.interactionSummary)
                    .question(record.interactionQuestion)
                    .pendingKind(record.kind)
                    .resourceIss(resourceIss)
                    .resourceScope(resourceScope)
                    .resourceMissionS256(resourceMissionS256)
                    .build();
        }
        if ("permission".equals(record.kind)) {
            return ConsentContext.builder(record.pendingId)
                    .justification(record.permissionDescription)
                    .mission(found)
                    .clarificationResponses(responses)
                    .pendingKind(record.kind)
                    .permissionAction(record.permissionAction)
                    .permissionDescription(record.permissionDescription)
                    .permissionParameters(record.permissionParameters)
                    .build();
        }
        return ConsentContext.builder(record.pendingId)
                .justification(justification)
                .mission(found)
                .clarificationResponses(responses)
                .pendingKind(record.kind)
                .resourceIss(resourceIss)
                .resourceScope(resourceScope)
                .resourceMissionS256(resourceMissionS256)
                .evaluatorReason(record.evaluatorReason)
                .build();
    }

    private Mission findMissionFor(PendingRecord record) {
        if ("mission".equals(record.kind) && record.missionProposal != null) {
            String agentId = record.missionProposal.agentId();
            for (Mission candidate : mission.listAllMissions()) {
                if (candidate.agentId().equals(agentId)) {
                    return candidate;
                }
            }
            return null;
        }
        if (("interaction".equals(record.kind) || "permission".equals(record.kind)) && record.missionS256 != null) {
            return mission.getMission(record.missionS256);
        }
        if ("token".equals(record.kind) && record.tokenRequest != null && record.tokenRequest.mission() != null) {
            return mission.getMission(record.tokenRequest.mission().s256());
        }
        return null;
    }

    private static String nonEmpty(Object value) {
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value);
        return text.isEmpty() ? null : text;
    }

    @Override
    public DecisionResult recordDecision(String pendingId, UserDecision decision) {
        PendingRecord record = store.getRecord(pendingId);

        if (decision.clarificationQuestion() != null
                && !decision.clarificationQuestion().isEmpty()) {
            store.updatePending(
                    pendingId,
                    new PendingUpdate(
                            PendingStatus.INTERACTING,
                            RequirementLevel.CLARIFICATION,
                            decision.clarificationQuestion(),
                            null,
                            null));
            return new DecisionResult(null);
        }

        // Permission pendings deliver granted/denied as a normal terminal body so the agent
        // gets a 200 response either way (Layer 2 — approved-tools gating).
        if ("permission".equals(record.kind)) {
            String result = decision.approved() ? "granted" : "denied";
            store.resolvePending(pendingId, new InteractionTerminalResult(Map.of("permission", result)));
            if (record.missionS256 != null && mission.hasMission(record.missionS256)) {
                Map<String, Object> payload = new HashMap<>();
                payload.put("action", record.permissionAction);
                payload.put("description", record.permissionDescription);
                payload.put("parameters", record.permissionParameters);
                payload.put("result", result);
                payload.put("decided_by", "user");
                mission.appendMissionLog(
                        record.missionS256, new MissionLogEntry(Instant.now(), MissionLogKind.PERMISSION, payload));
            }
            return new DecisionResult(record.callbackUrl);
        }

        if (!decision.approved()) {
            store.failPending(pendingId, "denied");
            return new DecisionResult(record.callbackUrl);
        }

        if ("interaction".equals(record.kind)) {
            return resolveInteraction(pendingId, record, decision);
        }

        if ("token".equals(record.kind) && record.tokenRequest != null) {
            return resolveToken(pendingId, record);
        }

        if ("mission".equals(record.kind) && record.missionProposal != null) {
            Mission approved = MissionUtils.missionFromProposal(record.missionProposal, psIssuer);
            recordMission(approved);
            store.resolvePending(pendingId, approved);
            return new DecisionResult(record.callbackUrl);
        }

        throw new NotFoundException();
    }

    private DecisionResult resolveInteraction(String pendingId, PendingRecord record, UserDecision decision) {
        if ("completion".equals(record.interactionType) && record.missionS256 != null) {
            Mission found = mission.getMission(record.missionS256);
            if (found != null && found.state() == MissionState.ACTIVE) {
                mission.setMission(found.withState(MissionState.TERMINATED));
                Map<String, Object> payload = new HashMap<>();
                payload.put("event", "mission_completed");
                payload.put("summary", record.interactionSummary);
                mission.appendMissionLog(
                        found.s256(), new MissionLogEntry(Instant.now(), MissionLogKind.AGENT_INTERACTION, payload));
            }
        }
        if ("question".equals(record.interactionType)) {
            String answer = decision.answerText() == null ? "" : decision.answerText();
            store.resolvePending(pendingId, new InteractionTerminalResult(Map.of("answer", answer)));
            return new DecisionResult(record.callbackUrl);
        }
        store.resolvePending(pendingId, new InteractionTerminalResult(Map.of("status", "ok")));
        return new DecisionResult(record.callbackUrl);
    }

    private DecisionResult resolveToken(String pendingId, PendingRecord record) {
        TokenRequest tokenRequest = record.tokenRequest;
        Map<String, Object> claims = resolvedResourceClaims(record, tokenRequest);
        TokenOutcome auth;
        if (tokenRequest.secureMode() && claims != null && !claims.isEmpty()) {
            String aud = IssuerUrls.normalizeAudClaim(claims.get("aud"));
            String normalizedPs = IssuerUrls.normalizeIssuer(psIssuer);
            Map<String, Object> cnf =
                    record.tokenAgentCnfJwk != null ? record.tokenAgentCnfJwk : tokenRequest.agentCnfJwk();
            if (IssuerUrls.issuerUrlsEquivalent(aud, normalizedPs) && cnf != null) {
                auth = authIssuer.issue(new AuthTokenIssuer.IssueSpec(
                        tokenRequest.agentId(),
                        new LinkedHashMap<>(cnf),
                        claims,
                        tokenRequest.mission(),
                        tokenRequest.justification(),
                        "user_consent"));
            } else {
                log.warn(
                        "consent: falling back to fake auth token (aud={} ps={} has_cnf={})",
                        aud,
                        normalizedPs,
                        cnf != null);
                auth = federator.requestAuthToken(
                        tokenRequest.resourceToken(), agentJwtStub, tokenRequest.upstreamToken());
            }
        } else {
            auth = federator.requestAuthToken(tokenRequest.resourceToken(), agentJwtStub, tokenRequest.upstreamToken());
        }
        if (!(auth instanceof AuthTokenResponse authToken)) {
            throw new IllegalStateException("federator unexpectedly deferred");
        }
        store.resolvePending(pendingId, authToken);
        if (tokenRequest.mission() != null) {
            String missionId = tokenRequest.mission().s256();
            if (mission.hasMission(missionId)) {
                Map<String, Object> payload = new HashMap<>();
                payload.put("justification", tokenRequest.justification());
                mission.appendMissionLog(
                        missionId, new MissionLogEntry(Instant.now(), MissionLogKind.TOKEN_REQUEST, payload));
            }
        }
        return new DecisionResult(record.callbackUrl);
    }

    @Override
    public void markInteracting(String pendingId) {
        store.updatePending(pendingId, PendingUpdate.ofStatus(PendingStatus.INTERACTING));
    }
}
