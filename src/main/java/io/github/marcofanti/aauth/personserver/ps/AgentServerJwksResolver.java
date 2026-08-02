package io.github.marcofanti.aauth.personserver.ps;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Supplier;

/** Callable {@code iss -> JWKS | null} for agent-token verification (trust + co-located AS). */
public final class AgentServerJwksResolver implements Function<String, Map<String, Object>> {

    private record CacheEntry(Map<String, Object> jwks, long storedNanos) {}

    private final String psOrigin;
    private final AgentServerTrustRegistry trust;
    private final Supplier<Map<String, Object>> selfJwksProvider;
    private final long ttlNanos;
    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();

    public AgentServerJwksResolver(
            String psOrigin, AgentServerTrustRegistry trust, Supplier<Map<String, Object>> selfJwksProvider) {
        this(psOrigin, trust, selfJwksProvider, 300);
    }

    public AgentServerJwksResolver(
            String psOrigin,
            AgentServerTrustRegistry trust,
            Supplier<Map<String, Object>> selfJwksProvider,
            long cacheTtlSeconds) {
        this.psOrigin = IssuerUrls.normalizeIssuer(psOrigin);
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

    @Override
    public Map<String, Object> apply(String iss) {
        String normalized = IssuerUrls.normalizeIssuer(iss);
        if (normalized.equals(psOrigin)) {
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
