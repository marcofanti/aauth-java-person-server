package io.github.marcofanti.aauth.personserver.ps;

/** Unknown mission or pending id; HTTP 404. */
public class NotFoundException extends PsException {

    public NotFoundException() {
        super("not found");
    }
}
