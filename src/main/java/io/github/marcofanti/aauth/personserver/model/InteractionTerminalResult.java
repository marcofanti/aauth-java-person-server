package io.github.marcofanti.aauth.personserver.model;

import java.util.Map;

/** Terminal payload when polling a pending URL for agent interaction / completion. */
public record InteractionTerminalResult(Map<String, Object> body) implements PendingPollOutcome, PendingStoreValue {}
