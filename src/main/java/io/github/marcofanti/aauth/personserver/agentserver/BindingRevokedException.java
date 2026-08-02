package io.github.marcofanti.aauth.personserver.agentserver;

public class BindingRevokedException extends AgentServerException {

    public BindingRevokedException() {
        super("binding revoked");
    }
}
