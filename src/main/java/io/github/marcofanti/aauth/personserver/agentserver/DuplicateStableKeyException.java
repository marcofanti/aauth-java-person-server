package io.github.marcofanti.aauth.personserver.agentserver;

/** A stable JKT is already registered on a binding (link dedup). */
public class DuplicateStableKeyException extends AgentServerException {

    public DuplicateStableKeyException() {
        super("stable key already registered on binding");
    }
}
