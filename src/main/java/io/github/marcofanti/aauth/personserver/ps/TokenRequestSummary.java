package io.github.marcofanti.aauth.personserver.ps;

/**
 * The slice of a token request the evaluator needs. Kept narrow on purpose — evaluators
 * must not depend on transport-level details.
 */
public record TokenRequestSummary(
        String agentId, String resourceIss, String resourceScope, String justification, boolean upstreamTokenPresent) {}
