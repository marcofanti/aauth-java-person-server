package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.model.DeferredResponse;
import io.github.marcofanti.aauth.personserver.model.PendingStatus;
import io.github.marcofanti.aauth.personserver.model.PendingStoreValue;
import io.github.marcofanti.aauth.personserver.model.TokenOutcome;
import io.github.marcofanti.aauth.personserver.model.TokenRequest;
import io.github.marcofanti.aauth.personserver.ps.AsFederator.Federation;
import io.github.marcofanti.aauth.personserver.web.ProblemError;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Passes an access server's 202 down to the agent (§9.1.2): the agent's pending request shows the
 * AS's interaction URL and code, or its question, and each agent poll polls the AS pending URL
 * once. An auth token from the AS resolves the pending once it passes the §9.1.3 checks; an AS
 * error ends it. Nothing runs in the background, so a pending survives a restart in SQL mode.
 */
public final class AsRelay {

    /** The AS is polled at most this often per pending, however fast the agent polls. */
    static final Duration MIN_AS_POLL_INTERVAL = Duration.ofSeconds(1);

    private final PendingRequestStore store;
    private final AsFederator federator;
    private final Map<String, Long> lastAsPoll = new ConcurrentHashMap<>();

    public AsRelay(PendingRequestStore store, AsFederator federator) {
        this.store = store;
        this.federator = federator;
    }

    /** The outcome of a federation step: the auth token, or a new pending that waits on the AS. */
    public TokenOutcome open(
            TokenRequest request, Map<String, Object> resourceClaims, Long deadline, Federation federation) {
        return switch (federation) {
            case Federation.Issued issued -> issued.token();
            case Federation.Deferred deferred -> {
                String pendingId = store.createPending(request);
                PendingRecord record = store.getRecord(pendingId);
                record.verifiedResourceClaims = resourceClaims;
                record.tokenAgentCnfJwk = request.agentCnfJwk();
                record.deadline = deadline;
                store.saveRecord(record);
                waitOn(pendingId, deferred.pending());
                if (!(store.getPending(pendingId, false) instanceof DeferredResponse response)) {
                    throw new IllegalStateException("a pending waiting on the AS is not deferred");
                }
                yield response;
            }
        };
    }

    /** Apply a federation step to the existing pending {@code pendingId}. */
    public void apply(String pendingId, Federation federation) {
        switch (federation) {
            case Federation.Issued issued -> {
                lastAsPoll.remove(pendingId);
                store.resolvePending(pendingId, issued.token());
            }
            case Federation.Deferred deferred -> waitOn(pendingId, deferred.pending());
        }
    }

    /** Whether {@code pendingId} waits on an AS. */
    public boolean waitsOnAs(String pendingId) {
        return store.getRecord(pendingId).asPendingUrl != null;
    }

    /**
     * Poll the AS once for a pending that waits on it, unless it was polled within
     * {@link #MIN_AS_POLL_INTERVAL}. A relayed AS error ends the pending with its code.
     */
    public void refresh(String pendingId) {
        PendingRecord record = store.getRecord(pendingId);
        if (record.asPendingUrl == null || record.terminal != null || record.failure != null || record.gone) {
            return;
        }
        long now = System.nanoTime();
        boolean[] due = {false};
        lastAsPoll.compute(pendingId, (id, last) -> {
            due[0] = last == null || now - last >= MIN_AS_POLL_INTERVAL.toNanos();
            return due[0] ? now : last;
        });
        if (!due[0]) {
            return;
        }
        step(
                pendingId,
                () -> federator.pollDraft11(record.tokenRequest, record.verifiedResourceClaims, record.asPendingUrl));
    }

    /** Forward the agent's answer to the AS's question (§7.5.2) and apply what the AS answers. */
    public PendingStoreValue clarify(String pendingId, String answer) {
        PendingRecord record = store.getRecord(pendingId);
        step(
                pendingId,
                () -> federator.clarifyDraft11(
                        record.tokenRequest, record.verifiedResourceClaims, record.asPendingUrl, answer));
        return store.getPending(pendingId, false);
    }

    private void step(String pendingId, java.util.function.Supplier<Federation> call) {
        try {
            apply(pendingId, call.get());
        } catch (ProblemError e) {
            lastAsPoll.remove(pendingId);
            store.failPending(pendingId, e.error());
        }
    }

    private void waitOn(String pendingId, AsPending pending) {
        PendingRecord record = store.getRecord(pendingId);
        record.asPendingUrl = pending.pendingUrl();
        record.relayUrl = pending.url();
        record.relayCode = pending.code();
        // Set, not merged: a requirement the AS dropped must not linger in what the agent sees.
        record.status = pending.interacting() ? PendingStatus.INTERACTING : PendingStatus.PENDING;
        record.requirement = pending.requirement();
        record.clarification = pending.clarification();
        record.timeout = pending.timeout();
        record.options = pending.options();
        store.saveRecord(record);
    }
}
