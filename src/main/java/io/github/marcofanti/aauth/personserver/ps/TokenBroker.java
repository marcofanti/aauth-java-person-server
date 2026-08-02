package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.model.DeferredResponse;
import io.github.marcofanti.aauth.personserver.model.PendingPollOutcome;
import io.github.marcofanti.aauth.personserver.model.TokenOutcome;
import io.github.marcofanti.aauth.personserver.model.TokenRequest;

/**
 * {@code token_endpoint} and pending URL operations for agents
 * (protocol §PS Token Endpoint, §Agent Response to Clarification).
 */
public interface TokenBroker {

    /** POST /token — may return auth token or deferred response. */
    TokenOutcome requestToken(TokenRequest request);

    /** GET pending URL — poll until 200 or terminal error (token or interaction result). */
    PendingPollOutcome getPending(String pendingId, String agentId);

    /** POST {@code clarification_response} to pending URL. */
    DeferredResponse postClarificationResponse(String pendingId, String agentId, String responseText);

    /** POST updated {@code resource_token} to pending URL. */
    DeferredResponse postUpdatedRequest(
            String pendingId, String agentId, String newResourceToken, String justification);

    /** DELETE pending URL — withdraw request. */
    void cancelRequest(String pendingId, String agentId);
}
