package io.github.marcofanti.aauth.personserver.agentserver;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** In-memory {@link IssuedAgentTokenStore} (dev / tests). */
public final class MemoryIssuedAgentTokenStore implements IssuedAgentTokenStore {

    private final Map<String, Issued> issued = new ConcurrentHashMap<>();

    @Override
    public void record(Issued token) {
        issued.putIfAbsent(token.jti(), token);
    }

    @Override
    public List<Issued> liveFor(String agentId, long nowEpochSeconds) {
        List<Issued> out = new ArrayList<>();
        for (Issued token : issued.values()) {
            if (token.agentId().equals(agentId) && token.exp() > nowEpochSeconds) {
                out.add(token);
            }
        }
        return out;
    }

    @Override
    public void purgeExpired(long nowEpochSeconds) {
        issued.values().removeIf(token -> token.exp() <= nowEpochSeconds);
    }
}
