package io.github.marcofanti.aauth.personserver.ps;

/** Base for Person Server domain errors surfaced by the HTTP layer. */
public abstract class PsException extends RuntimeException {

    protected PsException(String message) {
        super(message);
    }
}
