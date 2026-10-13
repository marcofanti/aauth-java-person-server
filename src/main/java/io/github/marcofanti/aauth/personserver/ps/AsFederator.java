package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.model.AuthTokenResponse;
import io.github.marcofanti.aauth.personserver.model.TokenOutcome;
import io.github.marcofanti.aauth.personserver.model.TokenRequest;
import io.github.marcofanti.aauth.personserver.web.ProblemError;
import java.util.Map;

/** PS-to-AS token endpoint federation (protocol §AS Token Endpoint, §PS-to-AS). */
public interface AsFederator {

    /** POST to AS {@code token_endpoint} with resource and agent tokens. */
    TokenOutcome requestAuthToken(String resourceToken, String agentToken, String upstreamToken);

    /** POST requested identity claims to the AS pending URL for {@code requirement=claims}. */
    TokenOutcome provideClaims(String pendingUrl, Map<String, Object> claims);

    /** GET the AS {@code Location} pending URL until a terminal response. */
    TokenOutcome pollAsPending(String pendingUrl);

    /** One step of draft-11 federation: the verified auth token, or the AS's 202 to pass down. */
    sealed interface Federation {

        /** The AS issued an auth token that passed the §9.1.3 delivery checks. */
        record Issued(AuthTokenResponse token) implements Federation {}

        /** The AS deferred with a requirement the agent or its person must meet (§9.1.2). */
        record Deferred(AsPending pending) implements Federation {}
    }

    /**
     * Draft-11 four-party (§9.1): request an auth token from the AS named by the resource token's
     * {@code aud}. Failures are {@link ProblemError}s to relay to the agent.
     */
    default Federation federateDraft11(TokenRequest request, Map<String, Object> resourceClaims) {
        throw new ProblemError(502, ProblemError.AS_UNREACHABLE, "this PS does not federate draft-11 requests");
    }

    /** Poll a deferred draft-11 request once at the AS pending URL {@code asPendingUrl}. */
    default Federation pollDraft11(TokenRequest request, Map<String, Object> resourceClaims, String asPendingUrl) {
        throw new ProblemError(502, ProblemError.AS_UNREACHABLE, "this PS does not federate draft-11 requests");
    }

    /** Deliver the agent's answer to an AS clarification at {@code asPendingUrl} (§7.5.2). */
    default Federation clarifyDraft11(
            TokenRequest request, Map<String, Object> resourceClaims, String asPendingUrl, String response) {
        throw new ProblemError(502, ProblemError.AS_UNREACHABLE, "this PS does not federate draft-11 requests");
    }
}
