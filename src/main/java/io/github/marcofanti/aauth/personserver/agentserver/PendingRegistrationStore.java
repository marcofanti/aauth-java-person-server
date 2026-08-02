package io.github.marcofanti.aauth.personserver.agentserver;

import io.github.marcofanti.aauth.personserver.model.PendingRegistration;
import java.util.List;
import java.util.Map;

/** Store for in-flight agent registrations (memory or SQL). */
public interface PendingRegistrationStore {

    PendingRegistration create(
            Map<String, Object> stablePub, Map<String, Object> ephemeralPub, String agentName, String stableJkt);

    /** Return the registration (auto-expiring pending → denied) or null when unknown. */
    PendingRegistration get(String pendingId);

    void approve(String pendingId);

    void deny(String pendingId);

    List<PendingRegistration> listPending();

    /** Return an in-flight (pending) registration with this stable JKT, if any. */
    PendingRegistration findByStableJkt(String stableJkt);
}
