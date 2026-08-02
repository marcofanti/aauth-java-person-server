package io.github.marcofanti.aauth.personserver.agentserver;

import io.github.marcofanti.aauth.personserver.model.PendingRegistration;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** In-memory {@link PendingRegistrationStore}. */
public final class MemoryPendingRegistrationStore implements PendingRegistrationStore {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final int defaultTtlSeconds;
    private final Map<String, PendingRegistration> store = new LinkedHashMap<>();

    public MemoryPendingRegistrationStore(int defaultTtlSeconds) {
        this.defaultTtlSeconds = defaultTtlSeconds;
    }

    public static String newId() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    @Override
    public synchronized PendingRegistration create(
            Map<String, Object> stablePub, Map<String, Object> ephemeralPub, String agentName, String stableJkt) {
        Instant now = Instant.now();
        PendingRegistration registration = new PendingRegistration(
                newId(),
                stablePub,
                ephemeralPub,
                agentName,
                stableJkt,
                now,
                now.plusSeconds(defaultTtlSeconds),
                "pending");
        store.put(registration.id(), registration);
        return registration;
    }

    @Override
    public synchronized PendingRegistration get(String pendingId) {
        PendingRegistration registration = store.get(pendingId);
        if (registration == null) {
            return null;
        }
        if ("pending".equals(registration.status()) && !Instant.now().isBefore(registration.expiresAt())) {
            registration = registration.withStatus("denied");
            store.put(pendingId, registration);
        }
        return registration;
    }

    @Override
    public synchronized void approve(String pendingId) {
        PendingRegistration registration = store.get(pendingId);
        if (registration == null) {
            throw new RegistrationNotFoundException();
        }
        store.put(pendingId, registration.withStatus("approved"));
    }

    @Override
    public synchronized void deny(String pendingId) {
        PendingRegistration registration = store.get(pendingId);
        if (registration == null) {
            throw new RegistrationNotFoundException();
        }
        store.put(pendingId, registration.withStatus("denied"));
    }

    @Override
    public synchronized List<PendingRegistration> listPending() {
        Instant now = Instant.now();
        List<PendingRegistration> out = new ArrayList<>();
        for (Map.Entry<String, PendingRegistration> entry : store.entrySet()) {
            PendingRegistration registration = entry.getValue();
            if ("pending".equals(registration.status()) && !now.isBefore(registration.expiresAt())) {
                registration = registration.withStatus("denied");
                entry.setValue(registration);
            }
            if ("pending".equals(registration.status())) {
                out.add(registration);
            }
        }
        out.sort(Comparator.comparing(PendingRegistration::createdAt));
        return out;
    }

    @Override
    public synchronized PendingRegistration findByStableJkt(String stableJkt) {
        Instant now = Instant.now();
        for (PendingRegistration registration : store.values()) {
            if (registration.stableJkt().equals(stableJkt)
                    && "pending".equals(registration.status())
                    && now.isBefore(registration.expiresAt())) {
                return registration;
            }
        }
        return null;
    }
}
