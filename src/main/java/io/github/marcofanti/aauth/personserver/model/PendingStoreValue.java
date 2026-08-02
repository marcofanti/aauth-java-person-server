package io.github.marcofanti.aauth.personserver.model;

/** Anything a pending row can hold: a deferred snapshot or a terminal success value. */
public sealed interface PendingStoreValue
        permits DeferredResponse, AuthTokenResponse, Mission, InteractionTerminalResult {}
