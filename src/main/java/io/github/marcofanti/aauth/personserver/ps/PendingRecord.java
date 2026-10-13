package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.model.MissionProposal;
import io.github.marcofanti.aauth.personserver.model.PendingStatus;
import io.github.marcofanti.aauth.personserver.model.PendingStoreValue;
import io.github.marcofanti.aauth.personserver.model.PersonTokenRequest;
import io.github.marcofanti.aauth.personserver.model.RequirementLevel;
import io.github.marcofanti.aauth.personserver.model.TokenRequest;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Mutable in-flight state of one deferred (202) flow — the direct port of the Python
 * {@code PendingRecord} dataclass. This is store-internal state, not a domain value:
 * consent decisions, clarifications, and evaluator verdicts mutate it in place, exactly
 * as the reference implementation does. Unlike the Python server (safe under uvicorn's
 * single-threaded event loop), Tomcat handles requests on parallel threads, so every
 * mutable field is volatile and the responses list is copy-on-write. {@code kind} is token | mission | interaction |
 * permission.
 */
public final class PendingRecord {

    public final String pendingId;
    public final String interactionCode;
    public final String kind;
    public final Instant createdAt;
    public volatile int ttlSeconds;
    public volatile TokenRequest tokenRequest;
    public volatile MissionProposal missionProposal;
    public volatile String ownerId;
    public volatile PendingStatus status = PendingStatus.PENDING;
    public volatile RequirementLevel requirement;
    public volatile String clarification;
    public volatile Integer timeout;
    public volatile List<String> options;
    public volatile PendingStoreValue terminal;
    public volatile String interactionType;
    public volatile String interactionSummary;
    public volatile String interactionQuestion;
    public volatile String relayUrl;
    public volatile String relayCode;
    public volatile String missionS256;
    public volatile String pendingAgentId;
    public volatile String interactionDescription;
    public volatile String permissionAction;
    public volatile String permissionDescription;
    public volatile Map<String, Object> permissionParameters;
    public volatile String failure;
    public volatile boolean gone;
    public volatile boolean delivered;
    public final List<String> clarificationResponses = new java.util.concurrent.CopyOnWriteArrayList<>();
    public volatile int clarificationRound;
    public volatile String callbackUrl;
    public volatile Long lastPollNanos;
    public volatile Map<String, Object> verifiedResourceClaims;
    public volatile Map<String, Object> tokenAgentCnfJwk;
    public volatile String evaluatorReason;
    public volatile PersonTokenRequest personTokenRequest;
    /** Epoch second after which the pending ends {@code expired} whatever its state (§10.1.1). */
    public volatile Long deadline;

    public PendingRecord(String pendingId, String interactionCode, String kind, Instant createdAt, int ttlSeconds) {
        this.pendingId = pendingId;
        this.interactionCode = interactionCode;
        this.kind = kind;
        this.createdAt = createdAt;
        this.ttlSeconds = ttlSeconds;
    }

    /** Whether this pending was started for the resource token {@code (iss, jti)}. */
    public boolean startedFor(String iss, String jti) {
        Map<String, Object> claims = verifiedResourceClaims;
        return claims != null
                && jti.equals(claims.get("jti"))
                && MissionUtils.stripTrailingSlash(iss)
                        .equals(MissionUtils.stripTrailingSlash(String.valueOf(claims.get("iss"))));
    }

    /**
     * Whether this pending relies on one of {@code jtis} (tokens this PS issued) as its presented
     * token or its upstream token, so revoking that token ends it (§11.12.4).
     */
    public boolean dependsOn(java.util.Set<String> jtis) {
        TokenRequest request = tokenRequest;
        if (request != null) {
            if (request.draft11() != null
                    && jtis.contains(jtiOf(request.draft11().presentedToken()))) {
                return true;
            }
            if (jtis.contains(jtiOf(request.upstreamToken()))) {
                return true;
            }
        }
        PersonTokenRequest personRequest = personTokenRequest;
        return personRequest != null
                && personRequest.upstream() != null
                && jtis.contains(personRequest.upstream().jti());
    }

    private static String jtiOf(String token) {
        if (token == null) {
            return null;
        }
        try {
            return io.github.marcofanti.aauth.signing.Jwts.parse(token).claim("jti");
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Agent id owning this pending row, from whichever request field is present. */
    public String agentId() {
        if (tokenRequest != null) {
            return tokenRequest.agentId();
        }
        if (missionProposal != null) {
            return missionProposal.agentId();
        }
        return pendingAgentId;
    }
}
