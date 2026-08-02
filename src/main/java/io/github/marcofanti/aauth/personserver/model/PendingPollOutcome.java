package io.github.marcofanti.aauth.personserver.model;

/** Outcome of polling a pending URL: token, still-deferred snapshot, or interaction result. */
public sealed interface PendingPollOutcome permits AuthTokenResponse, DeferredResponse, InteractionTerminalResult {}
