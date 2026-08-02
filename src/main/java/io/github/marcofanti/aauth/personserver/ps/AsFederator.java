package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.model.TokenOutcome;
import java.util.Map;

/** PS-to-AS token endpoint federation (protocol §AS Token Endpoint, §PS-to-AS). */
public interface AsFederator {

    /** POST to AS {@code token_endpoint} with resource and agent tokens. */
    TokenOutcome requestAuthToken(String resourceToken, String agentToken, String upstreamToken);

    /** POST requested identity claims to the AS pending URL for {@code requirement=claims}. */
    TokenOutcome provideClaims(String pendingUrl, Map<String, Object> claims);

    /** GET the AS {@code Location} pending URL until a terminal response. */
    TokenOutcome pollAsPending(String pendingUrl);
}
