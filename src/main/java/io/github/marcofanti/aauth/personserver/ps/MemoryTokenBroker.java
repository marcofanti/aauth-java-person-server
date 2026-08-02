package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.ErrorCodes;
import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.personserver.model.DeferredResponse;
import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionLogEntry;
import io.github.marcofanti.aauth.personserver.model.MissionLogKind;
import io.github.marcofanti.aauth.personserver.model.MissionRef;
import io.github.marcofanti.aauth.personserver.model.PendingPollOutcome;
import io.github.marcofanti.aauth.personserver.model.PendingStatus;
import io.github.marcofanti.aauth.personserver.model.PendingStoreValue;
import io.github.marcofanti.aauth.personserver.model.RequirementLevel;
import io.github.marcofanti.aauth.personserver.model.TokenOutcome;
import io.github.marcofanti.aauth.personserver.model.TokenRequest;
import io.github.marcofanti.aauth.personserver.ps.PendingRequestStore.PendingUpdate;
import io.github.marcofanti.aauth.tokens.ResourceTokens;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** In-memory {@link TokenBroker}: mode-3 resource token verification + PS-issued auth tokens. */
public final class MemoryTokenBroker implements TokenBroker {

    private static final Logger log = LoggerFactory.getLogger(MemoryTokenBroker.class);
    private static final int MAX_CLARIFICATION_ROUNDS = 5;

    private final PendingRequestStore store;
    private final AsFederator federator;
    private final MissionStatePort mission;
    private final String psOrigin;
    private final AuthTokenIssuer authIssuer;
    private final Function<String, Map<String, Object>> resourceJwks;
    private final ConsentScopeStore consentScopes;
    private final String agentJwtStub;
    private final boolean autoApproveWithoutConsent;
    private MissionEvaluator evaluator;

    @SuppressWarnings("ParameterNumber")
    public MemoryTokenBroker(
            PendingRequestStore store,
            AsFederator federator,
            MissionStatePort mission,
            String psOrigin,
            AuthTokenIssuer authIssuer,
            Function<String, Map<String, Object>> resourceJwks,
            ConsentScopeStore consentScopes,
            String agentJwtStub,
            boolean autoApproveWithoutConsent,
            MissionEvaluator evaluator) {
        this.store = store;
        this.federator = federator;
        this.mission = mission;
        this.psOrigin = IssuerUrls.normalizeIssuer(psOrigin);
        this.authIssuer = authIssuer;
        this.resourceJwks = resourceJwks;
        this.consentScopes = consentScopes;
        this.agentJwtStub = agentJwtStub;
        this.autoApproveWithoutConsent = autoApproveWithoutConsent;
        this.evaluator = evaluator;
    }

    /** Replace the Layer 1 evaluator (tests exercise forced allow/deny/clarify paths). */
    public void setEvaluator(MissionEvaluator evaluator) {
        this.evaluator = evaluator;
    }

    private Map<String, Object> verifyResourceToken(String resourceToken, String agentId, String agentJkt) {
        try {
            return ResourceTokens.verify(resourceToken, resourceJwks, null, agentId, agentJkt);
        } catch (TokenException e) {
            log.info("resource token verification failed: {}", e.getMessage());
            String code = e.getMessage() != null
                            && e.getMessage().toLowerCase(Locale.ROOT).contains("expired")
                    ? ErrorCodes.ERROR_EXPIRED_RESOURCE_TOKEN
                    : ErrorCodes.ERROR_INVALID_RESOURCE_TOKEN;
            throw new ResourceTokenRejectException(e.getMessage(), code);
        }
    }

    /** {@code aud} is PS → real auth token; otherwise existing fake AS federator. */
    private TokenOutcome issueOrFakeFederate(TokenRequest request, Map<String, Object> resourceClaims) {
        if (resourceClaims == null) {
            return federator.requestAuthToken(request.resourceToken(), agentJwtStub, request.upstreamToken());
        }
        String aud = IssuerUrls.normalizeAudClaim(resourceClaims.get("aud"));
        if (!IssuerUrls.issuerUrlsEquivalent(aud, psOrigin)) {
            return federator.requestAuthToken(request.resourceToken(), agentJwtStub, request.upstreamToken());
        }
        if (request.agentCnfJwk() == null) {
            throw new NotFoundException();
        }
        return authIssuer.issue(new AuthTokenIssuer.IssueSpec(
                request.agentId(),
                request.agentCnfJwk(),
                resourceClaims,
                request.mission(),
                request.justification(),
                "autonomous"));
    }

    @Override
    public TokenOutcome requestToken(TokenRequest request) {
        if (request.mission() != null) {
            MissionGuards.requireActiveMission(mission, request.mission());
        }

        Map<String, Object> resourceClaims = null;
        if (request.secureMode()) {
            resourceClaims = verifyResourceToken(request.resourceToken(), request.agentId(), request.agentJkt());
        }

        // Layer 1 — mission-aware evaluation. Runs whenever the request carries a mission
        // and an evaluator is wired, in both insecure and secure modes. The evaluator's
        // verdict overrides scope-based and auto shortcircuits below.
        String evaluatorEscalationReason = null;
        if (request.mission() != null && evaluator != null) {
            Mission active = mission.getMission(request.mission().s256());
            if (active != null) {
                EvaluatorOutcome outcome =
                        applyEvaluator(request, active, resourceClaims == null ? Map.of() : resourceClaims);
                switch (outcome) {
                    case EvaluatorOutcome.Issued issued -> {
                        return issued.outcome();
                    }
                    case EvaluatorOutcome.Clarify clarify -> {
                        return clarify.deferred();
                    }
                    case EvaluatorOutcome.Escalate escalate -> evaluatorEscalationReason = escalate.reason();
                }
            }
        }

        if (!request.secureMode()) {
            if (autoApproveWithoutConsent && evaluatorEscalationReason == null) {
                return federator.requestAuthToken(request.resourceToken(), agentJwtStub, request.upstreamToken());
            }
            return deferForConsent(request, null, evaluatorEscalationReason);
        }

        if (evaluatorEscalationReason == null
                && (autoApproveWithoutConsent
                        || !consentScopes.requiresConsent(stringOrNull(resourceClaims.get("scope"))))) {
            return issueOrFakeFederate(request, resourceClaims);
        }

        return deferForConsent(request, resourceClaims, evaluatorEscalationReason);
    }

    private TokenOutcome deferForConsent(
            TokenRequest request, Map<String, Object> resourceClaims, String evaluatorReason) {
        String pendingId = store.createPending(request);
        PendingRecord record = store.getRecord(pendingId);
        if (resourceClaims != null) {
            record.verifiedResourceClaims = resourceClaims;
            record.tokenAgentCnfJwk = request.agentCnfJwk();
        }
        if (evaluatorReason != null) {
            record.evaluatorReason = evaluatorReason;
        }
        store.updatePending(pendingId, PendingUpdate.ofRequirement(RequirementLevel.INTERACTION));
        PendingStoreValue value = store.getPending(pendingId, false);
        if (!(value instanceof TokenOutcome outcome)) {
            throw new NotFoundException();
        }
        return outcome;
    }

    private sealed interface EvaluatorOutcome {
        record Issued(TokenOutcome outcome) implements EvaluatorOutcome {}

        record Clarify(DeferredResponse deferred) implements EvaluatorOutcome {}

        record Escalate(String reason) implements EvaluatorOutcome {}
    }

    /** Run the evaluator, log the decision, and translate it into a control-flow shape. */
    private EvaluatorOutcome applyEvaluator(
            TokenRequest request, Mission activeMission, Map<String, Object> resourceClaims) {
        List<MissionLogEntry> logEntries = mission.getMissionLog(activeMission.s256());
        String iss = stringOrNull(resourceClaims.get("iss"));
        String scope = stringOrNull(resourceClaims.get("scope"));
        TokenRequestSummary summary = new TokenRequestSummary(
                request.agentId(), iss, scope, request.justification(), request.upstreamToken() != null);
        EvaluationDecision decision = evaluator.evaluate(activeMission, logEntries, summary);

        Map<String, Object> payload = new HashMap<>();
        payload.put("stage", "evaluator");
        payload.put("decision", decision.decision().value());
        payload.put("reason", decision.reason());
        payload.put("resource_iss", summary.resourceIss());
        payload.put("resource_scope", summary.resourceScope());
        payload.put("justification", request.justification());
        mission.appendMissionLog(
                activeMission.s256(), new MissionLogEntry(Instant.now(), MissionLogKind.TOKEN_REQUEST, payload));

        return switch (decision.decision()) {
            case DENY -> throw new MissionDeniedException(decision.reason());
            case ALLOW -> new EvaluatorOutcome.Issued(issueOrFakeFederate(request, emptyToNull(resourceClaims)));
            case CLARIFY -> {
                String pendingId = store.createPending(request);
                PendingRecord record = store.getRecord(pendingId);
                record.verifiedResourceClaims = emptyToNull(resourceClaims);
                record.tokenAgentCnfJwk = request.agentCnfJwk();
                record.evaluatorReason = decision.reason();
                store.updatePending(
                        pendingId,
                        new PendingUpdate(
                                PendingStatus.PENDING,
                                RequirementLevel.CLARIFICATION,
                                decision.clarificationQuestion(),
                                null,
                                null));
                PendingStoreValue out = store.getPending(pendingId, false);
                if (!(out instanceof DeferredResponse deferred)) {
                    throw new NotFoundException();
                }
                yield new EvaluatorOutcome.Clarify(deferred);
            }
            case ESCALATE -> new EvaluatorOutcome.Escalate(decision.reason());
        };
    }

    private static Map<String, Object> emptyToNull(Map<String, Object> claims) {
        return claims == null || claims.isEmpty() ? null : claims;
    }

    private static String stringOrNull(Object value) {
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value);
        return text.isEmpty() ? null : text;
    }

    @Override
    public PendingPollOutcome getPending(String pendingId, String agentId) {
        store.assertAgentOwnsPending(pendingId, agentId);
        PendingStoreValue value = store.getPending(pendingId, true);
        if (!(value instanceof PendingPollOutcome outcome)) {
            throw new NotFoundException();
        }
        return outcome;
    }

    @Override
    public DeferredResponse postClarificationResponse(String pendingId, String agentId, String responseText) {
        store.assertAgentOwnsPending(pendingId, agentId);
        PendingRecord record = store.getRecord(pendingId);
        if (record.clarificationRound >= MAX_CLARIFICATION_ROUNDS) {
            throw new ClarificationLimitException();
        }
        record.clarificationResponses.add(responseText);
        record.clarificationRound++;
        if (record.tokenRequest != null && record.tokenRequest.mission() != null) {
            MissionRef ref = record.tokenRequest.mission();
            mission.appendMissionLog(
                    ref.s256(),
                    new MissionLogEntry(Instant.now(), MissionLogKind.CLARIFICATION, Map.of("response", responseText)));
        }
        store.updatePending(
                pendingId, new PendingUpdate(PendingStatus.PENDING, RequirementLevel.INTERACTION, null, null, null));
        PendingStoreValue out = store.getPending(pendingId, false);
        if (out instanceof DeferredResponse deferred) {
            return deferred;
        }
        throw new IllegalStateException("unexpected terminal state after clarification");
    }

    @Override
    public DeferredResponse postUpdatedRequest(
            String pendingId, String agentId, String newResourceToken, String justification) {
        store.assertAgentOwnsPending(pendingId, agentId);
        store.replaceTokenRequest(pendingId, newResourceToken, justification);
        PendingRecord record = store.getRecord(pendingId);
        TokenRequest tokenRequest = record.tokenRequest;
        if (tokenRequest != null && tokenRequest.secureMode()) {
            record.verifiedResourceClaims =
                    verifyResourceToken(newResourceToken, tokenRequest.agentId(), tokenRequest.agentJkt());
        }
        store.updatePending(
                pendingId, new PendingUpdate(PendingStatus.PENDING, RequirementLevel.INTERACTION, null, null, null));
        PendingStoreValue out = store.getPending(pendingId, false);
        if (out instanceof DeferredResponse deferred) {
            return deferred;
        }
        throw new IllegalStateException("unexpected terminal state after updated request");
    }

    @Override
    public void cancelRequest(String pendingId, String agentId) {
        store.assertAgentOwnsPending(pendingId, agentId);
        store.deletePending(pendingId);
    }
}
