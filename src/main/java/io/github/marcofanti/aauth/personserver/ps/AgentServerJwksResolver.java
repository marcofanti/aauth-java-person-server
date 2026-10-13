package io.github.marcofanti.aauth.personserver.ps;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Supplier;

/** Callable {@code iss -> JWKS | null} for agent-token verification (trust + co-located AS). */
public final class AgentServerJwksResolver implements Function<String, Map<String, Object>> {

    private record CacheEntry(Map<String, Object> jwks, long storedNanos) {}

    private final String psOrigin;
    private final String selfAgentIssuer;
    private final AgentServerTrustRegistry trust;
    private final Supplier<Map<String, Object>> selfJwksProvider;
    private final long ttlNanos;
    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();

    public AgentServerJwksResolver(
            String psOrigin, AgentServerTrustRegistry trust, Supplier<Map<String, Object>> selfJwksProvider) {
        this(psOrigin, null, trust, selfJwksProvider);
    }

    /** {@code selfAgentIssuer}: the co-located Agent Server's own origin, or {@code null} if it shares the PS's. */
    public AgentServerJwksResolver(
            String psOrigin,
            String selfAgentIssuer,
            AgentServerTrustRegistry trust,
            Supplier<Map<String, Object>> selfJwksProvider) {
        this(psOrigin, selfAgentIssuer, trust, selfJwksProvider, 300);
    }

    public AgentServerJwksResolver(
            String psOrigin,
            String selfAgentIssuer,
            AgentServerTrustRegistry trust,
            Supplier<Map<String, Object>> selfJwksProvider,
            long cacheTtlSeconds) {
        this.psOrigin = IssuerUrls.normalizeIssuer(psOrigin);
        this.selfAgentIssuer = selfAgentIssuer == null ? null : IssuerUrls.normalizeIssuer(selfAgentIssuer);
        this.trust = trust;
        this.selfJwksProvider = selfJwksProvider;
        this.ttlNanos = cacheTtlSeconds * 1_000_000_000L;
    }

    private Map<String, Object> getCached(String key) {
        CacheEntry hit = cache.get(key);
        if (hit == null) {
            return null;
        }
        if (System.nanoTime() - hit.storedNanos() > ttlNanos) {
            cache.remove(key);
            return null;
        }
        return hit.jwks();
    }

    /** Whether {@code iss} is this PS, its co-located Agent Server, or an Agent Server it trusts. */
    public boolean isTrusted(String iss) {
        String normalized = IssuerUrls.normalizeIssuer(iss);
        return normalized.equals(psOrigin) || normalized.equals(selfAgentIssuer) || trust.isTrusted(normalized);
    }

    @Override
    public Map<String, Object> apply(String iss) {
        String normalized = IssuerUrls.normalizeIssuer(iss);
        if (normalized.equals(psOrigin) || normalized.equals(selfAgentIssuer)) {
            if (selfJwksProvider == null) {
                return null;
            }
            String key = "self:" + normalized;
            Map<String, Object> cached = getCached(key);
            if (cached != null) {
                return cached;
            }
            Map<String, Object> jwks = selfJwksProvider.get();
            cache.put(key, new CacheEntry(jwks, System.nanoTime()));
            return jwks;
        }
        if (!trust.isTrusted(normalized)) {
            return null;
        }
        String key = "trusted:" + normalized;
        Map<String, Object> cached = getCached(key);
        if (cached != null) {
            return cached;
        }
        Map<String, Object> jwks;
        try {
            jwks = SyncHttp.discoverJwksViaMetadata(normalized, "aauth-agent.json");
        } catch (IllegalArgumentException e) {
            return null;
        }
        cache.put(key, new CacheEntry(jwks, System.nanoTime()));
        return jwks;
    }
}
