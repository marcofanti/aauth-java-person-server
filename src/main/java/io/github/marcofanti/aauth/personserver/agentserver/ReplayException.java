package io.github.marcofanti.aauth.personserver.agentserver;

/** A replayed HTTP signature was detected. */
public class ReplayException extends AgentServerException {

    public ReplayException() {
        super("replayed HTTP signature");
    }
}
