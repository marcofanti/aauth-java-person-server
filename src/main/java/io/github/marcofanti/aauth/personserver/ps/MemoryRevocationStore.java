package io.github.marcofanti.aauth.personserver.ps;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** In-memory {@link RevocationStore} (dev / tests). */
public final class MemoryRevocationStore implements RevocationStore {

    private final Map<String, Long> revoked = new ConcurrentHashMap<>();
    private final Map<String, AgentToken> agentTokens = new ConcurrentHashMap<>();
    private final Map<String, Long> agentRevocations = new ConcurrentHashMap<>();
    private final java.util.Set<String> resourceIssuers = ConcurrentHashMap.newKeySet();
    private final ExpiredRecords expired = new ExpiredRecords();

    private record AgentToken(String sub, long exp) {}

    @Override
    public void recordResourceIssuer(String iss) {
        resourceIssuers.add(MissionUtils.stripTrailingSlash(iss));
    }

    @Override
    public boolean isKnownResourceIssuer(String iss) {
        return resourceIssuers.contains(MissionUtils.stripTrailingSlash(iss));
    }

    private static String key(String iss, String jti) {
        return MissionUtils.stripTrailingSlash(iss) + "\u0000" + jti;
    }

    @Override
    public void revoke(String iss, String jti, long exp) {
        revoked.putIfAbsent(key(iss, jti), exp);
        purgeIfDue();
    }

    @Override
    public boolean isRevoked(String iss, String jti) {
        return iss != null && jti != null && revoked.containsKey(key(iss, jti));
    }

    @Override
    public void recordAgentToken(String iss, String jti, String sub, long exp) {
        agentTokens.putIfAbsent(key(iss, jti), new AgentToken(sub, exp));
        purgeIfDue();
    }

    @Override
    public String agentSub(String iss, String jti) {
        AgentToken token = agentTokens.get(key(iss, jti));
        return token == null ? null : token.sub();
    }

    @Override
    public void recordAgentRevocation(String agentSub, long epochSeconds) {
        agentRevocations.merge(agentSub, epochSeconds, Math::max);
    }

    @Override
    public Long agentRevokedAt(String agentSub) {
        return agentRevocations.get(agentSub);
    }

    @Override
    public void purgeExpired(long cutoffEpochSeconds) {
        revoked.values().removeIf(exp -> exp <= cutoffEpochSeconds);
        agentTokens.values().removeIf(token -> token.exp() <= cutoffEpochSeconds);
    }

    private void purgeIfDue() {
        long cutoff = expired.cutoffIfDue();
        if (cutoff >= 0) {
            purgeExpired(cutoff);
        }
    }
}
