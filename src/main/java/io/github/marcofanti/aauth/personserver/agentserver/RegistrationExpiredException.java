package io.github.marcofanti.aauth.personserver.agentserver;

/** Pending registration TTL elapsed (Python: {@code PendingExpiredError}). */
public class RegistrationExpiredException extends AgentServerException {

    public RegistrationExpiredException() {
        super("pending registration expired");
    }
}
