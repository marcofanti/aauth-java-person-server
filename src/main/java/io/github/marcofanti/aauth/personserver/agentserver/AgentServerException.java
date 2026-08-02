package io.github.marcofanti.aauth.personserver.agentserver;

/** Base for Agent Server domain errors. */
public abstract class AgentServerException extends RuntimeException {

    protected AgentServerException(String message) {
        super(message);
    }
}
