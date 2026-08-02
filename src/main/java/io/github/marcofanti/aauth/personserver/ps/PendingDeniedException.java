package io.github.marcofanti.aauth.personserver.ps;

/** User or policy denied the request; HTTP 403. */
public class PendingDeniedException extends PsException {

    private final String reason;

    public PendingDeniedException() {
        this("denied");
    }

    public PendingDeniedException(String reason) {
        super(reason);
        this.reason = reason;
    }

    public String reason() {
        return reason;
    }
}
