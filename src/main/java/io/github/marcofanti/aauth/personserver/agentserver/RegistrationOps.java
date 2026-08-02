package io.github.marcofanti.aauth.personserver.agentserver;

import io.github.marcofanti.aauth.personserver.model.Binding;
import io.github.marcofanti.aauth.personserver.model.PendingRegistration;
import io.github.marcofanti.aauth.personserver.model.VerifiedRequest;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import java.time.Instant;
import java.util.Map;

/** Registration and pending-poll route logic (Python {@code registration_routes.py}). */
public final class RegistrationOps {

    /** Result of {@code POST /register}: immediate token or queued for approval. */
    public sealed interface RegisterResult {
        record Immediate(String agentToken) implements RegisterResult {}

        record Pending(String pendingId, Instant expiresAt) implements RegisterResult {}
    }

    /** Result of polling: still pending or token issued. */
    public sealed interface PollResult {
        record StillPending() implements PollResult {}

        record Token(String agentToken) implements PollResult {}
    }

    private RegistrationOps() {}

    public static String stableJktOf(Map<String, Object> stablePub) {
        return "urn:jkt:sha-256:" + Jwk.thumbprint(stablePub);
    }

    public static RegisterResult handleRegister(
            VerifiedRequest verified, Map<String, Object> stablePub, String agentName, AsContainer container) {
        String stableJkt = stableJktOf(stablePub);

        // Re-registration of a known device — issue token immediately, no approval needed.
        Binding existing = container.bindings().lookupByStableJkt(stableJkt);
        if (existing != null && !existing.revoked()) {
            container.bindings().updateAgentName(existing.agentId(), agentName);
            String token = container.signing().createAgentToken(existing.agentId(), verified.ephemeralPub(), null);
            return new RegisterResult.Immediate(token);
        }

        // New device — create a pending registration for person approval.
        PendingRegistration registration =
                container.registrations().create(stablePub, verified.ephemeralPub(), agentName, stableJkt);
        return new RegisterResult.Pending(registration.id(), registration.expiresAt());
    }

    public static PollResult handlePollPending(String pendingId, VerifiedRequest verified, AsContainer container) {
        PendingRegistration registration = container.registrations().get(pendingId);
        if (registration == null) {
            throw new RegistrationNotFoundException();
        }

        verifyEphemeralContinuity(verified, registration);

        if ("pending".equals(registration.status())) {
            if (!Instant.now().isBefore(registration.expiresAt())) {
                throw new RegistrationExpiredException();
            }
            return new PollResult.StillPending();
        }

        if ("denied".equals(registration.status())) {
            throw new RegistrationDeniedException();
        }

        // status == approved — binding was created at approval time; look it up.
        Binding binding = container.bindings().lookupByStableJkt(registration.stableJkt());
        if (binding == null || binding.revoked()) {
            throw new BindingNotFoundException();
        }
        String token = container.signing().createAgentToken(binding.agentId(), registration.ephemeralPub(), null);
        return new PollResult.Token(token);
    }

    /** Ensure the polling request is signed with the same ephemeral key used at registration. */
    private static void verifyEphemeralContinuity(VerifiedRequest verified, PendingRegistration registration) {
        Object registeredX = registration.ephemeralPub().get("x");
        Object presentedX = verified.ephemeralPub().get("x");
        if (registeredX == null || !registeredX.equals(presentedX)) {
            throw new InvalidSignatureException(
                    "Polling request must be signed with the same ephemeral key used at registration");
        }
    }

    /** {@code POST /refresh} — verified jkt-jwt chain; look up binding, issue a new token. */
    public static String handleRefresh(VerifiedRequest verified, AsContainer container) {
        if (!"jkt-jwt".equals(verified.scheme())) {
            throw new InvalidSignatureException(
                    "Refresh requires jkt-jwt Signature-Key scheme, got '" + verified.scheme() + "'");
        }
        String stableJkt = verified.stableJkt();
        if (stableJkt == null || stableJkt.isEmpty()) {
            throw new InvalidSignatureException("No stable JKT in verified request");
        }
        Binding binding = container.bindings().lookupByStableJkt(stableJkt);
        if (binding == null) {
            throw new BindingNotFoundException();
        }
        if (binding.revoked()) {
            throw new BindingRevokedException();
        }
        return container.signing().createAgentToken(binding.agentId(), verified.ephemeralPub(), null);
    }
}
