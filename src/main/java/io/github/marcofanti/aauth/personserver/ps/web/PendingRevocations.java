package io.github.marcofanti.aauth.personserver.ps.web;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Revocation cascades that outlasted the endpoint's hold and answered 202 (§11.12.3), by pending
 * id. Only the identity that made the revocation may poll one. In memory: a poll that reaches
 * another instance, or arrives after a restart or {@link #RETENTION}, gets 404, and the caller
 * may revoke again (revocation is idempotent).
 */
final class PendingRevocations {

    static final Duration RETENTION = Duration.ofMinutes(10);

    private record Entry(Object caller, CompletableFuture<?> cascade, Instant created) {}

    private final Map<String, Entry> entries = new ConcurrentHashMap<>();

    /** Track {@code cascade} for {@code caller}; returns the new pending id. */
    String add(Object caller, CompletableFuture<?> cascade) {
        Instant now = Instant.now();
        entries.values().removeIf(entry -> entry.created().plus(RETENTION).isBefore(now));
        String id = UUID.randomUUID().toString();
        entries.put(id, new Entry(caller, cascade, now));
        return id;
    }

    /** The cascade pending as {@code id}, or {@code null} if unknown or made by another caller. */
    CompletableFuture<?> find(String id, Object caller) {
        Entry entry = entries.get(id);
        return entry != null && entry.caller().equals(caller) ? entry.cascade() : null;
    }

    void remove(String id) {
        entries.remove(id);
    }
}
