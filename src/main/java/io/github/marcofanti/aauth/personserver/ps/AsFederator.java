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

    /**
     * Draft-11 four-party (§9.1): obtain and verify an auth token from the AS named by the
     * resource token's {@code aud}; failures are {@link ProblemError}s to relay to the agent.
     */
    default AuthTokenResponse federateDraft11(TokenRequest request, Map<String, Object> resourceClaims) {
        throw new ProblemError(502, ProblemError.AS_UNREACHABLE, "this PS does not federate draft-11 requests");
    }
}
