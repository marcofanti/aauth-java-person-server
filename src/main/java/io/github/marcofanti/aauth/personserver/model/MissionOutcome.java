package io.github.marcofanti.aauth.personserver.model;

/** Terminal or deferred outcome of {@code POST /mission}. */
public sealed interface MissionOutcome permits Mission, DeferredResponse {}
