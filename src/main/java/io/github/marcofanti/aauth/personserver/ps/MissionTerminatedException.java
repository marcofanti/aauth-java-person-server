package io.github.marcofanti.aauth.personserver.ps;

/** Referenced mission is not active; HTTP 403 mission_terminated. */
public class MissionTerminatedException extends PsException {

    public MissionTerminatedException() {
        super("mission terminated");
    }
}
