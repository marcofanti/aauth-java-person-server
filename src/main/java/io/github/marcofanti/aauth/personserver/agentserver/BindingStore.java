package io.github.marcofanti.aauth.personserver.agentserver;

import io.github.marcofanti.aauth.personserver.model.Binding;
import java.util.List;

/** Store for approved agent bindings (memory or SQL). */
public interface BindingStore {

    Binding create(String agentId, String agentName, String stableJkt);

    Binding lookupByStableJkt(String jkt);

    Binding getByAgentId(String agentId);

    void updateAgentName(String agentId, String agentName);

    List<Binding> listAll();

    /** Throws {@link DuplicateStableKeyException} when the JKT is already on the binding. */
    void addStableKey(String agentId, String stableJkt);

    void revoke(String agentId);
}
