package io.github.marcofanti.aauth.personserver.agentserver;

public class InvalidSignatureException extends AgentServerException {

    public InvalidSignatureException(String message) {
        super(message);
    }
}
