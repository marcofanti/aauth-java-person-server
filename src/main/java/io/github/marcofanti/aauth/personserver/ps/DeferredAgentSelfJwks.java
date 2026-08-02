package io.github.marcofanti.aauth.personserver.ps;

import java.util.Map;
import java.util.function.Supplier;

/** Set the supplier after the Agent Server container exists (unified portal startup). */
public final class DeferredAgentSelfJwks implements Supplier<Map<String, Object>> {

    private volatile Supplier<Map<String, Object>> delegate;

    public void set(Supplier<Map<String, Object>> supplier) {
        this.delegate = supplier;
    }

    @Override
    public Map<String, Object> get() {
        Supplier<Map<String, Object>> current = delegate;
        if (current == null) {
            throw new IllegalStateException("Agent self JWKS provider not wired (portal bug)");
        }
        return current.get();
    }
}
