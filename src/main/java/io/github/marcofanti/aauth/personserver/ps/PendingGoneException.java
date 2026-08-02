package io.github.marcofanti.aauth.personserver.ps;

/** Pending resource was cancelled; HTTP 410. */
public class PendingGoneException extends PsException {

    public PendingGoneException() {
        super("pending gone");
    }
}
