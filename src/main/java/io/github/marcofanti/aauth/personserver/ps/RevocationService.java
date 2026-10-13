package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.web.ProblemError;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The PS revocation endpoint's behavior (§11.12): record the {@code (iss, jti)} the verified
 * caller revoked, then run the cascade it implies and return once every downstream revocation
 * is terminal.
 *
 * <p>Agent providers revoke agent tokens; the PS then revokes, at their resources, every person
 * token and auth token it issued to that agent's {@code sub} (§11.12.4). Resources revoke
 * resource tokens; the PS refuses them from then on and ends the pending requests started for
 * them.
 */
public final class RevocationService {

    /** Who signed the revocation request, by the metadata document their key was found under. */
    public enum CallerKind {
        AGENT_PROVIDER,
        RESOURCE
    }

    /** One downstream revocation the cascade made, with its terminal outcome. */
    public record Downstream(String recipient, String jti, RevocationSender.Outcome outcome) {}

    /** The ports the cascade reads and the sender it revokes through. */
    public record Deps(
            RevocationStore revocations,
            PersonTokenLedger personTokens,
            IssuedTokenStore authTokens,
            PendingRequestStore pending,
            Sender sender) {}

    /** Revokes one token at one recipient, discovered from that recipient's metadata document. */
    @FunctionalInterface
    public interface Sender {
        RevocationSender.Outcome send(String recipient, String metadata, Token token);
    }

    /** A token the PS issued and now revokes downstream. */
    public record Token(String jti, long exp) {}

    private static final Logger log = LoggerFactory.getLogger(RevocationService.class);
    // Agent tokens SHOULD NOT outlive 24 hours (§5.3); a longer exp would only pin storage.
    private static final long MAX_TOKEN_LIFETIME_SECONDS = 86_400 + 300;
    private static final int MAX_PER_WINDOW = 100;
    private static final long WINDOW_SECONDS = 60;
    private static final int MAX_TRACKED_ISSUERS = 1_000;
    // Each downstream call is bounded by its own HTTP timeouts; this caps the whole cascade near
    // the ~20 s a caller is expected to hold (§11.12.3).
    private static final Duration CASCADE_TIMEOUT = Duration.ofSeconds(20);
    private static final ExecutorService DOWNSTREAM = Executors.newVirtualThreadPerTaskExecutor();

    private record Window(long start, int count) {}

    private final String psOrigin;
    private final Deps deps;
    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    public RevocationService(String psOrigin, Deps deps) {
        this.psOrigin = MissionUtils.stripTrailingSlash(psOrigin);
        this.deps = deps;
    }

    /**
     * Revoke {@code jti} in the namespace of {@code iss} and run its cascade.
     *
     * @return the downstream revocations made, each terminal; empty when nothing cascades
     */
    public List<Downstream> revoke(String iss, CallerKind kind, String jti, long exp) {
        long now = Instant.now().getEpochSecond();
        if (exp > now + MAX_TOKEN_LIFETIME_SECONDS) {
            throw new ProblemError(400, "invalid_request", "exp is further ahead than any token this PS accepts");
        }
        throttle(iss, now);
        deps.revocations().revoke(iss, jti, exp);
        if (kind == CallerKind.RESOURCE) {
            for (String pendingId : deps.pending().openPending(record -> record.startedFor(iss, jti))) {
                deps.pending().failPending(pendingId, "revoked");
            }
            return List.of();
        }
        String sub = deps.revocations().agentSub(iss, jti);
        if (sub == null) {
            return List.of();
        }
        deps.revocations().recordAgentRevocation(sub, now);
        return cascade(sub, now);
    }

    private void throttle(String iss, long now) {
        if (windows.size() > MAX_TRACKED_ISSUERS) {
            windows.values().removeIf(stale -> now - stale.start() >= WINDOW_SECONDS);
        }
        Window window = windows.compute(
                iss,
                (key, current) -> current == null || now - current.start() >= WINDOW_SECONDS
                        ? new Window(now, 1)
                        : new Window(current.start(), current.count() + 1));
        if (window.count() > MAX_PER_WINDOW) {
            int retryAfter = (int) Math.max(1, window.start() + WINDOW_SECONDS - now);
            throw new ProblemError(429, ProblemError.RATE_LIMITED, "too many revocations from this issuer", retryAfter);
        }
    }

    private record Target(String recipient, String metadata, Token token) {}

    /** §11.12.4: revoke every live person and auth token issued to the agent, wherever it went. */
    private List<Downstream> cascade(String agentSub, long now) {
        List<Target> targets = new ArrayList<>();
        // Revoked jtis whose derived person tokens (issued with them as upstream_token) follow.
        Deque<String> upstreams = new ArrayDeque<>();
        for (Map<String, Object> row : deps.authTokens().listIssued()) {
            Target target = liveAuthToken(row, agentSub, now);
            if (target != null) {
                targets.add(target);
                upstreams.add(target.token().jti());
            }
        }
        Deque<PersonTokenLedger.Issued> personTokens =
                new ArrayDeque<>(deps.personTokens().liveFor(agentSub, now));
        Set<String> seen = new HashSet<>();
        while (!personTokens.isEmpty() || !upstreams.isEmpty()) {
            if (!upstreams.isEmpty()) {
                personTokens.addAll(deps.personTokens().issuedFromUpstream(psOrigin, upstreams.pop()));
                continue;
            }
            PersonTokenLedger.Issued issued = personTokens.pop();
            if (issued.exp() <= now || !seen.add(issued.jti())) {
                continue;
            }
            Token token = new Token(issued.jti(), issued.exp());
            targets.add(new Target(issued.aud(), RevocationSender.RESOURCE_METADATA, token));
            for (PersonTokenLedger.Presentation presentation :
                    deps.personTokens().presentations(issued.jti())) {
                targets.add(new Target(presentation.asIssuer(), RevocationSender.ACCESS_METADATA, token));
            }
            upstreams.add(issued.jti());
        }
        Set<String> revoked = new HashSet<>();
        for (Target target : targets) {
            deps.revocations()
                    .revoke(psOrigin, target.token().jti(), target.token().exp());
            revoked.add(target.token().jti());
        }
        // Requests still waiting on this agent, or on a token just revoked, end now rather than
        // completing after the revocation (§11.12.4, polling error revoked).
        for (String pendingId :
                deps.pending().openPending(record -> agentSub.equals(record.agentId()) || record.dependsOn(revoked))) {
            deps.pending().failPending(pendingId, "revoked");
        }
        List<CompletableFuture<Downstream>> calls = new ArrayList<>();
        for (Target target : targets) {
            calls.add(CompletableFuture.supplyAsync(
                            () -> new Downstream(
                                    target.recipient(),
                                    target.token().jti(),
                                    deps.sender().send(target.recipient(), target.metadata(), target.token())),
                            DOWNSTREAM)
                    .completeOnTimeout(
                            new Downstream(
                                    target.recipient(),
                                    target.token().jti(),
                                    RevocationSender.Outcome.REVOCATION_UNAVAILABLE),
                            CASCADE_TIMEOUT.toSeconds(),
                            TimeUnit.SECONDS));
        }
        List<Downstream> outcomes = new ArrayList<>();
        for (CompletableFuture<Downstream> call : calls) {
            Downstream outcome = call.join();
            log.info(
                    "revocation cascade for {}: {} at {} -> {}",
                    agentSub,
                    outcome.jti(),
                    outcome.recipient(),
                    outcome.outcome());
            outcomes.add(outcome);
        }
        return outcomes;
    }

    private static Target liveAuthToken(Map<String, Object> row, String agentSub, long now) {
        if (!agentSub.equals(row.get("agent_id"))
                || !(row.get("token_jti") instanceof String jti)
                || !(row.get("resource_iss") instanceof String resource)) {
            return null;
        }
        long exp = expOf(row);
        return exp > now ? new Target(resource, RevocationSender.RESOURCE_METADATA, new Token(jti, exp)) : null;
    }

    private static long expOf(Map<String, Object> row) {
        Object expiresAt = row.get("expires_at");
        return expiresAt == null ? 0 : Instant.parse(String.valueOf(expiresAt)).getEpochSecond();
    }
}
