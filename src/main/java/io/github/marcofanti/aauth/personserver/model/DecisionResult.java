package io.github.marcofanti.aauth.personserver.model;

/** Outcome of {@code POST /consent/{pending_id}/decision}. */
public record DecisionResult(String redirectUrl) {}
