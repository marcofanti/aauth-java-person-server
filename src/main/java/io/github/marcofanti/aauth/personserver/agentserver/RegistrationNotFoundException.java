package io.github.marcofanti.aauth.personserver.agentserver;

/** Unknown pending registration id (Python: {@code PendingNotFoundError}). */
public class RegistrationNotFoundException extends AgentServerException {

    public RegistrationNotFoundException() {
        super("pending registration not found");
    }
}
