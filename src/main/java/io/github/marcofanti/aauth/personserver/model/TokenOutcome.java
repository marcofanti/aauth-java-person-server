package io.github.marcofanti.aauth.personserver.model;

/** Terminal or deferred outcome of {@code POST /token}. */
public sealed interface TokenOutcome permits AuthTokenResponse, DeferredResponse {}
