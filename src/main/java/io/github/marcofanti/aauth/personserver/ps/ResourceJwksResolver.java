package io.github.marcofanti.aauth.personserver.ps;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/** Callable {@code iss -> JWKS | null} for resource-token verification, with a TTL cache. */
public final class ResourceJwksResolver implements Function<String, Map<String, Object>> {

    private record CacheEntry(Map<String, Object> jwks, long storedNanos) {}

    private final long ttlNanos;
    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();

    public ResourceJwksResolver() {
        this(300);
    }

    public ResourceJwksResolver(long cacheTtlSeconds) {
        this.ttlNanos = cacheTtlSeconds * 1_000_000_000L;
    }

    @Override
    public Map<String, Object> apply(String iss) {
        String key = MissionUtils.stripTrailingSlash(iss);
        CacheEntry hit = cache.get(key);
        if (hit != null) {
            if (System.nanoTime() - hit.storedNanos() <= ttlNanos) {
                return hit.jwks();
            }
            cache.remove(key);
        }
        Map<String, Object> jwks;
        try {
            jwks = SyncHttp.discoverJwksViaMetadata(key, "aauth-resource.json");
        } catch (IllegalArgumentException e) {
            return null;
        }
        cache.put(key, new CacheEntry(jwks, System.nanoTime()));
        return jwks;
    }
}
