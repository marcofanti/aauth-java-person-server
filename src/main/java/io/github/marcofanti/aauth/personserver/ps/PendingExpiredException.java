package io.github.marcofanti.aauth.personserver.ps;

/** Pending request timed out; HTTP 408. */
public class PendingExpiredException extends PsException {

    public PendingExpiredException() {
        super("pending expired");
    }
}
