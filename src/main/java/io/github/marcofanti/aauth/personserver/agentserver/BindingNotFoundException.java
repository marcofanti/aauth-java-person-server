package io.github.marcofanti.aauth.personserver.agentserver;

public class BindingNotFoundException extends AgentServerException {

    public BindingNotFoundException() {
        super("binding not found");
    }
}
