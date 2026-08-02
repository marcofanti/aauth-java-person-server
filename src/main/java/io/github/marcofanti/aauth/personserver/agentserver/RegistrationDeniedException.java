package io.github.marcofanti.aauth.personserver.agentserver;

/** Person denied the registration (Python: {@code PendingDeniedError}). */
public class RegistrationDeniedException extends AgentServerException {

    public RegistrationDeniedException() {
        super("pending registration denied");
    }
}
