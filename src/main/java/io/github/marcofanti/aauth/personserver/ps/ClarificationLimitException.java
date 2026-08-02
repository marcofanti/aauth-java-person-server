package io.github.marcofanti.aauth.personserver.ps;

/** Too many clarification rounds; HTTP 400. */
public class ClarificationLimitException extends PsException {

    public ClarificationLimitException() {
        super("clarification limit reached");
    }
}
