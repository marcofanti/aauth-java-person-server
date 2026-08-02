package io.github.marcofanti.aauth.personserver.ps;

/** Unknown or already-used interaction code; HTTP 410. */
public class InvalidInteractionCodeException extends PsException {

    public InvalidInteractionCodeException() {
        super("invalid interaction code");
    }
}
