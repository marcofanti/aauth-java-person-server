package io.github.marcofanti.aauth.personserver.ps;

/** Polling too frequently; HTTP 429. */
public class SlowDownException extends PsException {

    public SlowDownException() {
        super("slow down");
    }
}
