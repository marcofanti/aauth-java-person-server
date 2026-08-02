package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.model.ConsentContext;
import io.github.marcofanti.aauth.personserver.model.DecisionResult;
import io.github.marcofanti.aauth.personserver.model.UserDecision;

/**
 * User-facing consent surface — session-based auth, not agent HTTP signatures
 * (protocol §User Interaction).
 */
public interface UserConsent {

    /** Resolve interaction {@code code} to what the user should see. */
    ConsentContext getConsentContext(String code);

    /** Apply approve / deny / clarification question. */
    DecisionResult recordDecision(String pendingId, UserDecision decision);

    /** User arrived; pending body {@code status} becomes {@code interacting}. */
    void markInteracting(String pendingId);
}
