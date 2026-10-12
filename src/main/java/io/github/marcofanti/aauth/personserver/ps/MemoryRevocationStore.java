package io.github.marcofanti.aauth.personserver.ps;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** In-memory {@link RevocationStore} (dev / tests). */
public final class MemoryRevocationStore implements RevocationStore {

    private final Map<String, Long> revoked = new ConcurrentHashMap<>();
    private final Map<String, String> agentSubs = new ConcurrentHashMap<>();

    private static String key(String iss, String jti) {
        return MissionUtils.stripTrailingSlash(iss) + "\u0000" + jti;
    }

    @Override
    public void revoke(String iss, String jti, long exp) {
        revoked.putIfAbsent(key(iss, jti), exp);
    }

    @Override
    public boolean isRevoked(String iss, String jti) {
        return iss != null && jti != null && revoked.containsKey(key(iss, jti));
    }

    @Override
    public void recordAgentToken(String iss, String jti, String sub, long exp) {
        agentSubs.putIfAbsent(key(iss, jti), sub);
    }

    @Override
    public String agentSub(String iss, String jti) {
        return agentSubs.get(key(iss, jti));
    }
}
