package io.github.marcofanti.aauth.personserver.agentserver;

import io.github.marcofanti.aauth.personserver.model.Binding;
import io.github.marcofanti.aauth.personserver.model.PendingRegistration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Person-facing route logic: approval/denial/linking, binding management. */
public final class PersonOps {

    private PersonOps() {}

    /** {@code POST /person/registrations/{id}/approve} — create binding, mark approved. */
    public static Map<String, Object> handleApprove(String pendingId, AsContainer container, String serverDomain) {
        PendingRegistration registration = container.registrations().get(pendingId);
        if (registration == null) {
            throw new RegistrationNotFoundException();
        }
        if (!"pending".equals(registration.status())) {
            throw new IllegalArgumentException(
                    "Registration " + pendingId + " is not pending (status=" + registration.status() + ")");
        }
        String agentId = AgentIds.generateAgentId(serverDomain);
        Binding binding = container.bindings().create(agentId, registration.agentName(), registration.stableJkt());
        container.registrations().approve(pendingId);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("agent_id", binding.agentId());
        out.put("agent_name", binding.agentName());
        return out;
    }

    public static void handleDeny(String pendingId, AsContainer container) {
        if (container.registrations().get(pendingId) == null) {
            throw new RegistrationNotFoundException();
        }
        container.registrations().deny(pendingId);
    }

    /** {@code POST /person/registrations/{id}/link} — add device to existing binding. */
    public static Map<String, Object> handleLink(String pendingId, String targetAgentId, AsContainer container) {
        PendingRegistration registration = container.registrations().get(pendingId);
        if (registration == null) {
            throw new RegistrationNotFoundException();
        }
        if (!"pending".equals(registration.status())) {
            throw new IllegalArgumentException(
                    "Registration " + pendingId + " is not pending (status=" + registration.status() + ")");
        }
        Binding binding = container.bindings().getByAgentId(targetAgentId);
        if (binding == null || binding.revoked()) {
            throw new BindingNotFoundException();
        }
        container.bindings().addStableKey(targetAgentId, registration.stableJkt());
        container.registrations().approve(pendingId);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("agent_id", binding.agentId());
        out.put("agent_name", registration.agentName());
        return out;
    }

    public static List<Map<String, Object>> handleListRegistrations(AsContainer container) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (PendingRegistration registration : container.registrations().listPending()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("id", registration.id());
            row.put("agent_name", registration.agentName());
            row.put("stable_jkt", registration.stableJkt());
            row.put("created_at", PyIso.format(registration.createdAt()));
            row.put("expires_at", PyIso.format(registration.expiresAt()));
            row.put("status", registration.status());
            out.add(row);
        }
        return out;
    }

    public static List<Map<String, Object>> handleListBindings(AsContainer container) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Binding binding : container.bindings().listAll()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("agent_id", binding.agentId());
            row.put("agent_name", binding.agentName());
            row.put("created_at", PyIso.format(binding.createdAt()));
            row.put("device_count", binding.stableKeyThumbprints().size());
            row.put("stable_key_thumbprints", binding.stableKeyThumbprints());
            row.put("revoked", binding.revoked());
            out.add(row);
        }
        return out;
    }

    public static void handleRevokeBinding(String agentId, AsContainer container) {
        if (container.bindings().getByAgentId(agentId) == null) {
            throw new BindingNotFoundException();
        }
        container.bindings().revoke(agentId);
    }

    /** {@code POST /person/bindings} — trust a stable public JWK without a pending registration. */
    public static Map<String, Object> handleCreateBindingFromStablePub(
            Map<String, Object> stablePub, String agentName, AsContainer container, String serverDomain) {
        String stableJkt;
        try {
            stableJkt = RegistrationOps.stableJktOf(stablePub);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("Invalid stable_pub JWK", e);
        }
        Binding existing = container.bindings().lookupByStableJkt(stableJkt);
        if (existing != null && !existing.revoked()) {
            throw new StableKeyAlreadyBoundException(existing.agentId());
        }
        String agentId = AgentIds.generateAgentId(serverDomain);
        Binding binding = container.bindings().create(agentId, agentName, stableJkt);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("agent_id", binding.agentId());
        out.put("agent_name", binding.agentName());
        out.put("stable_jkt", stableJkt);
        return out;
    }
}
