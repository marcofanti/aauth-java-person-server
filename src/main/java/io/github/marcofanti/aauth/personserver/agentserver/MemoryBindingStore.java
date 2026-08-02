package io.github.marcofanti.aauth.personserver.agentserver;

import io.github.marcofanti.aauth.personserver.model.Binding;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** In-memory {@link BindingStore}. */
public final class MemoryBindingStore implements BindingStore {

    private final Map<String, Binding> byAgentId = new LinkedHashMap<>();
    private final Map<String, String> jktIndex = new LinkedHashMap<>();

    @Override
    public synchronized Binding create(String agentId, String agentName, String stableJkt) {
        Binding binding = new Binding(agentId, agentName, Instant.now(), List.of(stableJkt), false);
        byAgentId.put(agentId, binding);
        jktIndex.put(stableJkt, agentId);
        return binding;
    }

    @Override
    public synchronized Binding lookupByStableJkt(String jkt) {
        String agentId = jktIndex.get(jkt);
        return agentId == null ? null : byAgentId.get(agentId);
    }

    @Override
    public synchronized Binding getByAgentId(String agentId) {
        return byAgentId.get(agentId);
    }

    @Override
    public synchronized void updateAgentName(String agentId, String agentName) {
        Binding binding = byAgentId.get(agentId);
        if (binding == null) {
            throw new BindingNotFoundException();
        }
        byAgentId.put(
                agentId,
                new Binding(
                        binding.agentId(),
                        agentName.strip(),
                        binding.createdAt(),
                        binding.stableKeyThumbprints(),
                        binding.revoked()));
    }

    @Override
    public synchronized List<Binding> listAll() {
        List<Binding> out = new ArrayList<>(byAgentId.values());
        out.sort(Comparator.comparing(Binding::createdAt));
        return out;
    }

    @Override
    public synchronized void addStableKey(String agentId, String stableJkt) {
        Binding binding = byAgentId.get(agentId);
        if (binding == null) {
            throw new BindingNotFoundException();
        }
        if (binding.stableKeyThumbprints().contains(stableJkt)) {
            throw new DuplicateStableKeyException();
        }
        byAgentId.put(agentId, binding.withAddedThumbprint(stableJkt));
        jktIndex.put(stableJkt, agentId);
    }

    @Override
    public synchronized void revoke(String agentId) {
        Binding binding = byAgentId.get(agentId);
        if (binding == null) {
            throw new BindingNotFoundException();
        }
        byAgentId.put(agentId, binding.withRevoked(true));
    }
}
