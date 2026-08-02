package io.github.marcofanti.aauth.personserver.agentserver;

/** Person tried to create a binding for a stable key that already has an active binding. */
public class StableKeyAlreadyBoundException extends AgentServerException {

    private final String agentId;

    public StableKeyAlreadyBoundException(String agentId) {
        super("This stable key is already bound to active agent " + agentId + ".");
        this.agentId = agentId;
    }

    public String agentId() {
        return agentId;
    }
}
