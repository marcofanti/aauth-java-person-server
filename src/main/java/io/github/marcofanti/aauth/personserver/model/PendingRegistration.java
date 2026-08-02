package io.github.marcofanti.aauth.personserver.model;

import java.time.Instant;
import java.util.Map;

/**
 * Pending agent registration. {@code stablePub}/{@code ephemeralPub} are JWKs;
 * {@code stableJkt} is {@code urn:jkt:sha-256:<thumbprint>}; {@code status} is
 * pending | approved | denied.
 */
public record PendingRegistration(
        String id,
        Map<String, Object> stablePub,
        Map<String, Object> ephemeralPub,
        String agentName,
        String stableJkt,
        Instant createdAt,
        Instant expiresAt,
        String status) {

    public PendingRegistration withStatus(String newStatus) {
        return new PendingRegistration(
                id, stablePub, ephemeralPub, agentName, stableJkt, createdAt, expiresAt, newStatus);
    }
}
