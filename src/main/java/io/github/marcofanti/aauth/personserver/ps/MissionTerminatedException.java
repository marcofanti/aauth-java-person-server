package io.github.marcofanti.aauth.personserver.ps;

/** Referenced mission is not active; HTTP 403 mission_terminated (draft-11 §8.8). */
public class MissionTerminatedException extends PsException {

    private final String reason;

    public MissionTerminatedException() {
        this(null);
    }

    /** @param reason the draft-11 termination reason (§8.6), or {@code null} when unknown */
    public MissionTerminatedException(String reason) {
        super("mission terminated");
        this.reason = reason;
    }

    public String reason() {
        return reason;
    }
}
